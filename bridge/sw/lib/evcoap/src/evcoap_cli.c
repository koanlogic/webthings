#include <strings.h>
#include <string.h>
#include <event2/event.h>
#include <event2/util.h>
#include <u/libu.h>
#include "evcoap_cli.h"
#include "evcoap_base.h"
#include "evcoap_debug.h"

#define NO_STRING(s)  ((s) == NULL || *(s) == '\0')

static int ec_client_check_transition(ec_cli_state_t cur, ec_cli_state_t next);
static bool ec_client_state_is_final(ec_cli_state_t state);
static ec_net_cbrc_t ec_client_handle_pdu(uint8_t *raw, size_t raw_sz, int sd,
        struct sockaddr_storage *peer, void *arg);
static void ec_cli_app_timeout(evutil_socket_t u0, short u1, void *c);
static void ec_cli_coap_timeout(evutil_socket_t u0, short u1, void *c);
static void ec_client_dns_cb(int result, struct evutil_addrinfo *res, void *a);
static int ec_client_check_req_token(ec_client_t *cli);
static int ec_client_invoke_user_callback(ec_client_t *cli);

int ec_client_set_method(ec_client_t *cli, ec_method_t m)
{
    ec_flow_t *flow = &cli->flow;

    dbg_return_if (!EC_IS_METHOD(m), -1);

    flow->method = m;

    return 0;
}

int ec_client_set_proxy(ec_client_t *cli, const char *host, uint16_t port)
{
    ec_conn_t *conn = &cli->flow.conn;

    dbg_return_if (NO_STRING(host), -1);

    conn->proxy_port = (port == 0) ? EC_COAP_DEFAULT_PORT : port;

    dbg_err_if (u_strlcpy(conn->proxy_addr, host, sizeof conn->proxy_addr));

    conn->use_proxy = 1;

    return 0;
err:
    return -1;
}

int ec_client_set_uri(ec_client_t *cli, const char *uri)
{
    ec_opts_t *opts;
    ec_conn_t *conn;
    const char *scheme, *host, *p;
    u_uri_t *u = NULL;

    opts = &cli->req.opts;
    conn = &cli->flow.conn;

    /* Do minimal URI validation: parse it according to STD 66 + expect
     * at least non empty scheme and host. */
    dbg_err_if (u_uri_crumble(uri, 0, &u));
    dbg_err_if ((scheme = u_uri_get_scheme(u)) == NULL || *scheme == '\0');
    dbg_err_if ((host = u_uri_get_host(u)) == NULL || *host == '\0');

    /* Set options. */
    if (conn->use_proxy)
        dbg_err_if (ec_opts_add_proxy_uri(opts, uri));
    else
    {
        /* Expect scheme==coap for any non proxy request. */
        if (strcasecmp(scheme, "coap"))
            dbg_err("expect URI with coap scheme on non-proxy requests");

        dbg_err_if (ec_opts_add_uri_host(opts, host));

        if ((p = u_uri_get_port(u)) && *p != '\0')
        {
            int port;

            dbg_err_if (u_atoi(p, &port));
            dbg_err_if (ec_opts_add_uri_port(opts, (uint16_t) port));
        }

        /* Separate path components. */
        if ((p = u_uri_get_path(u)) && *p != '\0')
        {
            char *r, *s, path[1024];    /* TODO check path len. */

            dbg_err_if (u_strlcpy(path, p, sizeof path));

            for (s = path; (r = strsep(&s, "/")) != NULL; )
            {
                if (*r == '\0')
                    continue;

                dbg_err_if (ec_opts_add_uri_path(opts, r));
            }
        }

        /* Add query, if available. */
        if ((p = u_uri_get_query(u)) && *p != '\0')
            dbg_err_if (ec_opts_add_uri_query(opts, p));
    }

    u_uri_free(u);

    return 0;
err:
    if (u)
        u_uri_free(u);
    return -1;
}

void ec_client_free(ec_client_t *cli)
{
    if (cli)
    {
        ec_t *coap = cli->base;
        ec_flow_t *flow = &cli->flow;
        ec_conn_t *conn = &flow->conn;

        /* Unregister me from list of clients and events. */
        ec_client_unregister(cli);

        /* Close socket. */
        evutil_closesocket(conn->socket);

        /* Free URI. */
        u_uri_free(flow->uri);

        ec_res_set_clear(&cli->res_set);
        ec_opts_clear(&cli->req.opts);

        u_free(cli);
    }

    return;
}

int ec_client_set_msg_model(ec_client_t *cli, bool is_con)
{
    dbg_return_if (cli == NULL, -1);

    return ec_net_set_confirmable(&cli->flow.conn, is_con);
}

ec_client_t *ec_client_new(struct ec_s *coap, ec_method_t m, const char *uri, 
        ec_msg_model_t mm, const char *proxy_host, uint16_t proxy_port)
{
    ec_client_t *cli = NULL;

    dbg_return_if (coap == NULL, NULL);
    /* Assume all other input parameters are checked by called functions. */

    dbg_err_sif ((cli = u_zalloc(sizeof *cli)) == NULL);

    dbg_err_if (ec_res_set_init(&cli->res_set));

    /* Must be done first because the following URI validation (namely the
     * scheme compliance test) depends on the fact that this request is 
     * expected to go through a proxy or not. */
    if (proxy_host)
        dbg_err_if (ec_client_set_proxy(cli, proxy_host, proxy_port));

    dbg_err_if (ec_pdu_init_options(&cli->req));
    dbg_err_if (ec_client_set_method(cli, m));
    dbg_err_ifm (ec_client_set_uri(cli, uri), "bad URI: %s", uri);
    dbg_err_if (ec_client_set_msg_model(cli, mm == EC_CON ? true : false));
    dbg_err_if (ec_pdu_set_flow(&cli->req, &cli->flow));

    /* Cache the base so that we don't need to pass it around every function
     * that manipulates the transaction. */
    cli->base = coap;

    return cli;
err:
    if (cli)
        ec_client_free(cli);
    return NULL;
}

int ec_client_go(ec_client_t *cli, ec_client_cb_t cb, void *cb_args,
        struct timeval *tout)
{
    ec_pdu_t *req;
    ec_flow_t *flow;
    ec_conn_t *conn;
    ec_cli_timers_t *timers;
    ec_opt_t *pu = NULL;
    const char *host;
    uint16_t port;
    char sport[16];
    struct evutil_addrinfo hints;
    struct timeval app_tout_dflt = { 
        .tv_sec = EC_TIMERS_APP_TOUT, 
        .tv_usec = 0
    };

    dbg_return_if (cli == NULL, -1);

    /* Expect client with state NONE.  Otherwise we jump to err where the 
     * state is set to INTERNAL_ERR. */
    dbg_err_ifm (cli->state != EC_CLI_STATE_NONE,
            "unexpected state %u", cli->state);

    req = &cli->req;
    flow = &cli->flow;
    timers = &cli->timers;
    conn = &flow->conn;

    /* TODO Sanitize request. */ 

    /* Add a Token option, if missing. */
    dbg_err_if (ec_client_check_req_token(cli));

    /* Get destination for this flow. */
    if (conn->use_proxy)
    {
        /* Use user supplied proxy host and port (assume previous sanitization
         * done by ec_client_set_proxy(). */
        host = conn->proxy_addr;
        port = conn->proxy_port;
    }
    else
    {
        /* Use Uri-Host + optional Uri-Port */
        dbg_err_if ((host = ec_opts_get_uri_host(&req->opts)) == NULL);

        if (ec_opts_get_uri_port(&req->opts, &port))
            port = EC_COAP_DEFAULT_PORT;
    }

    dbg_err_if (u_snprintf(sport, sizeof sport, "%u", port));

    /* Set user defined callback. */
    cli->cb = cb;
    cli->cb_args = cb_args;

    /* Set application timeout. */
    timers->app_tout = tout ? *tout : app_tout_dflt;

    /* Set up hints needed by evdns_getaddrinfo(). */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = 0;

    /* Pass the ball to evdns.  In case the evdns resolved immediately,
     * we return the send operation status hold by pdu->state.
     * Otherwise return ok and let the status of the send operation be 
     * given back to the user supplied callback.
     * Save the evdns_getaddrinfo_request pointer (may be NULL in case
     * of immediate resolution) so that the request can be canceled 
     * in a later moment if needed. */
    cli->dns_req = evdns_getaddrinfo(cli->base->dns, host, sport, &hints, 
            ec_client_dns_cb, cli);

    /* If we get here, either the client FSM has reached a final state (since
     * the callback has been shortcircuited), or the it's not yet started. */
    return 0;
err:
    (void) ec_client_set_state(cli, EC_CLI_STATE_INTERNAL_ERR);
    return -1;
}

static void ec_client_dns_cb(int result, struct evutil_addrinfo *res, void *a)
{
#define EC_CLI_ASSERT(e, state)                     \
    do {                                            \
        if ((e))                                    \
        {                                           \
            (void) ec_client_set_state(cli, state); \
            goto err;                               \
        }                                           \
    } while (0)

    struct evutil_addrinfo *ai = NULL;
    ec_client_t *cli = (ec_client_t *) a;
    ec_pdu_t *req = &cli->req;
    ec_conn_t *conn = &cli->flow.conn;
    ec_dups_t *dups = &cli->base->dups;

    /* Unset the evdns_getaddrinfo_request pointer, since when we get called
     * its lifetime is complete. */
    cli->dns_req = NULL;

    EC_CLI_ASSERT(result != DNS_ERR_NONE, EC_CLI_STATE_DNS_FAILED);

    (void) ec_client_set_state(cli, EC_CLI_STATE_DNS_OK);

    /* Encode options and header. */
    EC_CLI_ASSERT(ec_pdu_encode_request(req), EC_CLI_STATE_INTERNAL_ERR);

    for (conn->socket = -1, ai = res; ai != NULL; ai = ai->ai_next)
    {
        conn->socket = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

        if (conn->socket == -1)
           continue;

        dbg_err_if (ec_pdu_set_peer(req,
                    (struct sockaddr_storage *) ai->ai_addr));

        /* Send the request PDU. */
        if (ec_pdu_send(req, dups))
        {
            /* Mark this socket as failed and try again. */
            evutil_closesocket(conn->socket), conn->socket = -1;
            continue;
        }

        EC_CLI_ASSERT(evutil_make_socket_nonblocking(conn->socket),
                EC_CLI_STATE_INTERNAL_ERR);

        (void) ec_client_set_state(cli, EC_CLI_STATE_REQ_SENT);
        break;
    }

    /* Check whether the request PDU was actually sent out on any socket. */
    EC_CLI_ASSERT(conn->socket == -1, EC_CLI_STATE_INTERNAL_ERR);

    /* Add this to the pending clients' list. */
    EC_CLI_ASSERT(ec_client_register(cli), EC_CLI_STATE_INTERNAL_ERR);

    /* TODO add to the duplicate machinery ? */

    /* Remove the heap-allocated evutil_addrinfo's linked list. */
    if (ai)
        evutil_freeaddrinfo(ai);

    return;
err:
    if (ai)
        evutil_freeaddrinfo(ai);
    return;
    /* TODO Invoke user callback with the failure code. */
#undef EC_CLI_ASSERT
}

static int ec_client_check_transition(ec_cli_state_t cur, ec_cli_state_t next)
{
    switch (next)
    {
        /* Any state can switch to INTERNAL_ERROR. */
        case EC_CLI_STATE_INTERNAL_ERR:
            break;

        case EC_CLI_STATE_DNS_FAILED:
        case EC_CLI_STATE_DNS_OK:
            dbg_err_if (cur != EC_CLI_STATE_NONE);
            break;

        case EC_CLI_STATE_SEND_FAILED:
        case EC_CLI_STATE_REQ_SENT:
            dbg_err_if (cur != EC_CLI_STATE_DNS_OK
                    && cur != EC_CLI_STATE_COAP_RETRY);
            break;

        case EC_CLI_STATE_REQ_ACKD:
        case EC_CLI_STATE_COAP_RETRY:
        case EC_CLI_STATE_COAP_TIMEOUT:
            dbg_err_if (cur != EC_CLI_STATE_REQ_SENT);
            break;

        case EC_CLI_STATE_APP_TIMEOUT:
        case EC_CLI_STATE_REQ_DONE:
        case EC_CLI_STATE_REQ_RST:
        case EC_CLI_STATE_WAIT_NFY:
            dbg_err_if (cur != EC_CLI_STATE_REQ_SENT
                    && cur != EC_CLI_STATE_REQ_ACKD);
            break;

        case EC_CLI_STATE_NONE:
        default:
            goto err;
    }

    return 0;
err:
    u_warn("invalid transition from '%s' to '%s'", ec_cli_state_str(cur),
            ec_cli_state_str(next));
    return -1;
}

static bool ec_client_state_is_final(ec_cli_state_t state)
{
    switch (state)
    {
        case EC_CLI_STATE_INTERNAL_ERR:
        case EC_CLI_STATE_DNS_FAILED:
        case EC_CLI_STATE_SEND_FAILED:
        case EC_CLI_STATE_COAP_TIMEOUT:
        case EC_CLI_STATE_APP_TIMEOUT:
        case EC_CLI_STATE_REQ_DONE:
        case EC_CLI_STATE_REQ_RST:
            return true;
        case EC_CLI_STATE_NONE:
        case EC_CLI_STATE_DNS_OK:
        case EC_CLI_STATE_REQ_SENT:
        case EC_CLI_STATE_REQ_ACKD:
        case EC_CLI_STATE_COAP_RETRY:
        case EC_CLI_STATE_WAIT_NFY:
            return false;
        default:
            die(EXIT_FAILURE, "%s: no such state %u", __func__, state);
    }
}

static void ec_cli_coap_timeout(evutil_socket_t u0, short u1, void *c)
{
    ec_client_t *cli = (ec_client_t *) c;
    ec_dups_t *dups = &cli->base->dups;
    ec_cli_timers_t *t = &cli->timers;

    /* First off: check if we've got here with all retransmit attempts 
     * depleted. */
    if (t->nretry == EC_COAP_MAX_RETRANSMIT)
    {
        (void) ec_client_set_state(cli, EC_CLI_STATE_COAP_TIMEOUT);
    }
    else
    {
        /* Enter the RETRY state and try to send the PDU again. */
        (void) ec_client_set_state(cli, EC_CLI_STATE_COAP_RETRY);

        if (ec_pdu_send(&cli->req, dups) == 0)
            (void) ec_client_set_state(cli, EC_CLI_STATE_REQ_SENT);
        else
            (void) ec_client_set_state(cli, EC_CLI_STATE_SEND_FAILED);
    }

    return;
}

int ec_cli_restart_coap_timer(ec_client_t *cli)
{
    dbg_return_if (cli == NULL, -1);

    ec_t *coap = cli->base;
    ec_cli_timers_t *t = &cli->timers;

    /* Double timeout value. */
    t->coap_tout.tv_sec *= 2;

    u_dbg("timeout = %d", t->coap_tout.tv_sec);

    /* Add timeout to the base. */
    dbg_err_if (evtimer_add(t->coap, &t->coap_tout));

    /* Increment number of retries. */
    ++t->nretry;

    return 0;
err:
    (void) ec_cli_stop_coap_timer(cli);
    return -1;

}

int ec_cli_start_coap_timer(ec_client_t *cli)
{
    dbg_return_if (cli == NULL, -1);

    ec_t *coap = cli->base;
    ec_cli_timers_t *t = &cli->timers;

    /* Set initial timeout value (TODO randomization.) */
    t->coap_tout.tv_sec = EC_COAP_RESPONSE_TIMEOUT;

    /* Create new CoAP (non persisten) timeout event for this client. */
    t->coap = evtimer_new(coap->base, ec_cli_coap_timeout, cli);

    /* Add timeout to the base. */
    dbg_err_if (t->coap == NULL || evtimer_add(t->coap, &t->coap_tout));

    t->nretry = 1;

    return 0;
err:
    (void) ec_cli_stop_coap_timer(cli);
    return -1;
}

static void ec_cli_app_timeout(evutil_socket_t u0, short u1, void *c)
{
    ec_client_t *cli = (ec_client_t *) c;

    /* Set state to APP_TIMEOUT. */
    (void) ec_client_set_state(cli, EC_CLI_STATE_APP_TIMEOUT);

    return;
}

int ec_cli_stop_coap_timer(ec_client_t *cli)
{
    ec_cli_timers_t *t;

    dbg_return_if (cli == NULL, -1);

    t = &cli->timers;

    if (t->coap)
    {
        event_free(t->coap);
        t->coap = NULL;
        /* TODO clean nretry and coap_tout ? */
    }

    return 0;
}

int ec_cli_start_app_timer(ec_client_t *cli)
{
    dbg_return_if (cli == NULL, -1);

    ec_t *coap = cli->base;
    ec_cli_timers_t *t = &cli->timers;

    /* It is expected that the application timeout is set only once for each
     * client. */
    dbg_err_if (t->app != NULL);

    u_dbg("application timeout is %d seconds", t->app_tout.tv_sec);

    t->app = evtimer_new(coap->base, ec_cli_app_timeout, cli);
    dbg_err_if (t->app == NULL || evtimer_add(t->app, &t->app_tout));

    return 0;
err:
    if (t->app)
        event_free(t->app);
    return -1;
}

int ec_cli_stop_app_timer(ec_client_t *cli)
{
    dbg_return_if (cli == NULL, -1);

    ec_cli_timers_t *t = &cli->timers;

    if (t->app)
    {
        event_free(t->app);
        t->app = NULL;
    }

    return 0;
}

/* Returns true on a final state, false otherwise.
 * Failure is not an option :-) */
bool ec_client_set_state(ec_client_t *cli, ec_cli_state_t state)
{
    ec_cli_state_t cur = cli->state;
    bool is_con = false, is_final_state = false;

    u_dbg("[client=%p] transition request from '%s' to '%s'", cli, 
            ec_cli_state_str(cur), ec_cli_state_str(state));

    /* Check that the requested state transition is valid. */
    dbg_err_if (ec_client_check_transition(cur, state));

    /* Try to get the type of message flow. */
    dbg_if (ec_net_get_confirmable(&cli->flow.conn, &is_con));

    if (state == EC_CLI_STATE_REQ_SENT)
    {
        if (cur == EC_CLI_STATE_DNS_OK)
        {
            /* After the *first* successful send, start the application 
             * timeout. */
            dbg_err_if (ec_cli_start_app_timer(cli));

            /* In case it's a CON flow, also start the retransmission timer. */
            dbg_if (is_con && ec_cli_start_coap_timer(cli));
        }
        else if (cur == EC_CLI_STATE_COAP_RETRY)
        {
            /* Restart timer. */
            dbg_if (ec_cli_restart_coap_timer(cli));
        }
    }
    else if ((is_final_state = ec_client_state_is_final(state)))
    {
        /* Any final state MUST destroy all pending timers. */
        dbg_if (ec_cli_stop_app_timer(cli));

        /* If CON also stop the retransmission timer. */
        dbg_if (is_con && ec_cli_stop_coap_timer(cli));
    }

    /* Finally set state and, in case the state we've entered is final, 
     * invoke the user callback. */
    cli->state = state;

    if (is_final_state)
    {
        (void) ec_client_invoke_user_callback(cli);

        /* We can now finish off with this client. */
        ec_client_free(cli);
    }

    return is_final_state;
err:
    /* Should never happen ! */
    die(EXIT_FAILURE, "%s failed (see logs)", __func__);
}

int ec_client_register(ec_client_t *cli)
{
    ec_t *coap;
    ec_conn_t *conn;
    struct event *ev_input = NULL;

    dbg_return_if (cli == NULL, -1);
        
    coap = cli->base;
    conn = &cli->flow.conn;

    /* Attach server response events to this socket. */
    dbg_err_if ((ev_input = event_new(coap->base, conn->socket, 
                    EV_READ | EV_PERSIST, ec_client_input, cli)) == NULL);

    /* Make the read event pending in the base. */
    dbg_err_if (event_add(ev_input, NULL) == -1);
    
    /* Attach input event on this socket. */
    conn->ev_input = ev_input, ev_input = NULL;

    TAILQ_INSERT_HEAD(&coap->clients, cli, next);

    return 0;
err:
    if (ev_input)
        event_del(ev_input);
    return -1;
}

int ec_client_unregister(ec_client_t *cli)
{
    ec_t *coap;
    ec_conn_t *conn;

    dbg_return_if (cli == NULL, -1);

    coap = cli->base;
    conn = &cli->flow.conn;

    if (conn->ev_input)
        event_free(conn->ev_input);

    if (coap)
        TAILQ_REMOVE(&coap->clients, cli, next);

    return 0;
}

/* XXX bad function name, could lead to confusion. */
struct ec_s *ec_client_get_base(ec_client_t *cli)
{
    dbg_return_if (cli == NULL, NULL);

    return cli->base;
}

ec_cli_state_t ec_client_get_state(ec_client_t *cli)
{
    /* We don't have any meaningful return code to return in case a NULL
     * client was supplied.  Trace this into the log just before we core 
     * dump on subsequent dereference attempt. */
    dbg_if (cli == NULL);

    return cli->state;
}

static ec_net_cbrc_t ec_client_handle_pdu(uint8_t *raw, size_t raw_sz, int sd,
        struct sockaddr_storage *peer, void *arg)
{
    ec_opt_t *t;
    ec_client_t *cli;
    size_t olen = 0, plen;
    ec_pdu_t *res = NULL;

    dbg_return_if ((cli = (ec_client_t *) arg) == NULL, EC_NET_CBRC_ERROR);

    /* Make room for the new PDU. */
    dbg_err_sif ((res = ec_pdu_new_empty()) == NULL);

    /* Decode CoAP header and save it into the client context. */
    dbg_err_if (ec_pdu_decode_header(res, raw, raw_sz));

    ec_hdr_t *h = &res->hdr_bits;   /* shortcut */
    ec_flow_t *flow = &cli->flow;   /* shortcut */

    dbg_err_ifm (h->code >= 1 && h->code <= 31, 
            "unexpected request code in client response context");

    /* Pass MID and peer address to the dup handler machinery. */
    ec_dups_t *dups = &cli->base->dups;

    /* See return codes of evcoap_base.c:ec_dups_handle_incoming_res().
     *
     * TODO Keep an eye here, if we can factor out code in common with 
     * TODO ec_server_handle_pdu(). */
    switch (ec_dups_handle_incoming_srvmsg(dups, h->mid, sd, peer))
    {
        case 0:
            /* Not a duplicate, proceed with normal processing. */
            break;
        case 1:
            /* Duplicate, possible resending of the paired message is handled 
             * by ec_dups_handle_incoming_srvmsg(). */
            goto cleanup;
        default:
            /* Internal error. */
            u_dbg("Duplicate handling machinery failed !");
            goto err;
    }
    
    /* Handle empty responses (i.e. resets and separated acknowledgements)
     * specially. */
    if (!h->code)
    {
        dbg_err_if (ec_client_handle_empty_pdu(cli, h->t, h->mid));
        goto cleanup;
    }

    /* Parse options.  At least one option (namely the Token) must be present
     * because evcoap always sends one non-empty Token to its clients. */
    dbg_err_ifm (!h->oc, "no options in response !");
    dbg_err_ifm (ec_opts_decode(&res->opts, raw, raw_sz, h->oc, &olen),
            "CoAP options could not be parsed correctly");

    /* Check that there is a token and it matches the one we sent out with the 
     * request. */
    dbg_err_if ((t = ec_opts_get(&res->opts, EC_OPT_TOKEN)) == NULL);
    dbg_err_if (t->l != flow->token_sz || memcmp(t->v, flow->token, t->l));

    /* Attach response code. */
    dbg_err_if (ec_flow_set_resp_code(flow, (ec_rc_t) h->code));

    /* Attach payload, if any. */
    if ((plen = raw_sz - (olen + EC_COAP_HDR_SIZE)))
        (void) ec_pdu_set_payload(res, raw + EC_COAP_HDR_SIZE + olen, plen);

    /* TODO fill in the residual info (e.g. socket...). */

    /* Add response PDU to the client response set. */
    dbg_err_if (ec_res_set_add(&cli->res_set, res));

    /* Just before invoking the client callback, set state to DONE.
     * If state is final, make the caller aware through EC_NET_CBRC_DEAD
     * which signals that the client context is not available anymore. */
    if (ec_client_set_state(cli, EC_CLI_STATE_REQ_DONE) == true)
        return EC_NET_CBRC_DEAD;

    return EC_NET_CBRC_SUCCESS;

cleanup:
    ec_pdu_free(res);

    return EC_NET_CBRC_SUCCESS;
err:
    if (res)
        ec_pdu_free(res);

    return EC_NET_CBRC_ERROR;
}

static int ec_client_invoke_user_callback(ec_client_t *cli)
{
    dbg_return_if (cli == NULL, -1);

    if (cli->cb)
        cli->cb(cli);
    else
    {
        /* TODO respond something standard in case there's no callback. */
    }

    return 0;
}

int ec_client_handle_empty_pdu(ec_client_t *cli, uint8_t t, uint16_t mid)
{
    /* TODO */
    return 0;
}

/* Just a wrapper around ec_net_pullup_all(). */
void ec_client_input(evutil_socket_t sd, short u, void *arg)
{
    ec_client_t *cli = (ec_client_t *) arg;

    u_unused_args(u);

    ec_net_pullup_all(sd, ec_client_handle_pdu, cli);
}

void *ec_client_get_args(ec_client_t *cli)
{
    dbg_return_if (cli == NULL, NULL);

    return cli->cb_args;
}

static int ec_client_check_req_token(ec_client_t *cli)
{
    ec_opt_t *t;
    ec_flow_t *flow;
    ec_pdu_t *req;
    uint8_t tok[8];
    const size_t tok_sz = sizeof tok;

    dbg_return_if (cli == NULL, -1);

    req = &cli->req;    /* shortcut */
    flow = &cli->flow;  /* ditto */

    if ((t = ec_opts_get(&req->opts, EC_OPT_TOKEN)) == NULL)
    {
        evutil_secure_rng_get_bytes(tok, tok_sz);
        dbg_err_if (ec_opts_add_token(&req->opts, tok, tok_sz));
    }

    /* Cache the token value into the flow. */
    dbg_err_if (ec_flow_save_token(flow, t ? t->v : tok, t ? t->l : tok_sz));
 
    return 0;
err:
    /* Since failure is critical remove all added opts. */
    ec_opts_clear(&req->opts);

    return -1;
}

int ec_res_set_add(ec_res_set_t *rset, ec_pdu_t *pdu)
{
    dbg_return_if (rset == NULL, -1);
    dbg_return_if (pdu == NULL, -1);

    TAILQ_INSERT_TAIL(&rset->bundle, pdu, next);
    rset->nres += 1;

    return 0;
}

int ec_res_set_init(ec_res_set_t *rset)
{
    dbg_return_if (rset == NULL, -1);

    TAILQ_INIT(&rset->bundle);
    rset->nres = 0;

    return 0;
}

int ec_res_set_clear(ec_res_set_t *rset)
{
    if (rset)
    {
        ec_pdu_t *pdu;

        while ((pdu = TAILQ_FIRST(&rset->bundle)))
        {
            TAILQ_REMOVE(&rset->bundle, pdu, next);
            ec_pdu_free(pdu);
            /* Don't mind updating rset->nres since it'll be cleared. */
        }

        (void) ec_res_set_init(rset);
    }

    return 0;
}

ec_pdu_t *ec_client_get_request_pdu(ec_client_t *cli)
{
    dbg_return_if (cli == NULL, NULL);

    return &cli->req;
}

ec_opts_t *ec_client_get_request_options(ec_client_t *cli)
{
    ec_pdu_t *req;
    ec_opts_t *opts;

    dbg_return_if (cli == NULL, NULL);

    dbg_err_if ((req = ec_client_get_request_pdu(cli)) == NULL);

    return &req->opts;
err:
    return NULL;
}


/* Unicast only. */
ec_pdu_t *ec_client_get_response_pdu(ec_client_t *cli)
{
    ec_conn_t *conn;
    ec_res_set_t *rset;

    dbg_return_if (cli == NULL, NULL);

    /* Accept unicast only. */
    conn = &cli->flow.conn;
    dbg_err_ifm (conn->is_multicast, "use TODO interface for multicast res");

    /* Get the reponse set. */
    rset = &cli->res_set;
    dbg_err_if (!rset->nres);

    return TAILQ_FIRST(&rset->bundle);
err:
    return NULL;
}

ec_opts_t *ec_client_get_response_options(ec_client_t *cli)
{
    ec_pdu_t *res;
    ec_opts_t *opts;

    dbg_return_if (cli == NULL, NULL);

    dbg_err_if ((res = ec_client_get_response_pdu(cli)) == NULL);

    return &res->opts;
err:
    return NULL;
}

