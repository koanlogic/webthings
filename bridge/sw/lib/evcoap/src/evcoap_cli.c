#include <strings.h>
#include <string.h>
#include <event2/event.h>
#include <event2/util.h>
#include <u/libu.h>
#include "evcoap.h"
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
static void ec_cli_obs_timeout(evutil_socket_t u0, short u1, void *c);
static int ec_client_handle_observation(ec_client_t *cli);
static void ec_client_dns_cb(int result, struct evutil_addrinfo *res, void *a);
static int ec_client_check_req_token(ec_client_t *cli);
static int ec_client_invoke_user_callback(ec_client_t *cli);
static int ec_cli_timer_start(ec_client_t *cli, ec_cli_timer_t *ti, 
        size_t max_retry, void (*cb)(evutil_socket_t, short, void *));
static int ec_cli_timer_remove(ec_cli_timer_t *ti);
static int ec_cli_timer_restart(ec_cli_timer_t *ti);
static int ec_cli_obs_init(ec_cli_obs_t *obs);

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

    /* It will be possibly set in case response confirms the observation. */
    ec_cli_obs_init(&cli->observe);

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
    timers->app.tout = tout ? *tout : app_tout_dflt;

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
            dbg_err_if (cur != EC_CLI_STATE_REQ_SENT
                    && cur != EC_CLI_STATE_REQ_ACKD);
            break;

        case EC_CLI_STATE_WAIT_NFY:
            dbg_err_if (cur != EC_CLI_STATE_REQ_SENT
                    && cur != EC_CLI_STATE_REQ_ACKD
                    && cur != EC_CLI_STATE_WAIT_NFY);
            break;

        case EC_CLI_STATE_OBS_TIMEOUT:
            dbg_err_if (cur != EC_CLI_STATE_WAIT_NFY);
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
        case EC_CLI_STATE_OBS_TIMEOUT:
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
    ec_cli_timer_t *ti = &cli->timers.coap;

    /* First off: check if we've got here with all retransmit attempts 
     * depleted. */
    if (ti->retries_left == 0)
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

/* The 'ti' object shall enter here with the .tout field already set by the
 * caller. */
static int ec_cli_timer_start(ec_client_t *cli, ec_cli_timer_t *ti, 
        size_t max_retry, void (*cb)(evutil_socket_t, short, void *))
{

    dbg_return_if (cli == NULL, -1);
    dbg_return_if (ti == NULL, -1);
    dbg_return_if (cb == NULL, -1);
    dbg_return_if (!max_retry, -1);

    dbg_return_ifm (ti->evti != NULL, -1,
            "timer %p already initialized !", ti->evti);

    ec_t *coap = cli->base;   /* Shortcut. */

    ti->retries_left = max_retry;

    /* Create and start timer. */
    dbg_err_if ((ti->evti = evtimer_new(coap->base, cb, cli)) == NULL);
    dbg_err_if (evtimer_add(ti->evti, &ti->tout));

    return 0;
err:
    ec_cli_timer_remove(ti);
    return -1;
}

static int ec_cli_timer_remove(ec_cli_timer_t *ti)
{
    dbg_return_if (ti == NULL, -1);

    if (ti->evti)
    {
        event_free(ti->evti);
        ti->evti = NULL;
        ti->retries_left = 0;
        /* Don't cleanup .tout which may be reused. */
    }

    return 0;
}

static int ec_cli_timer_restart(ec_cli_timer_t *ti)
{
    dbg_return_if (ti == NULL, -1);

    /* Drop it in case the old instance is pending in the base, and
     * make it newly active with the configured timeout. */
    dbg_return_if (evtimer_del(ti->evti), -1);
    dbg_return_if (evtimer_add(ti->evti, &ti->tout), -1);

    return 0;
}

int ec_cli_start_coap_timer(ec_client_t *cli)
{
    dbg_return_if (cli == NULL, -1);

    ec_cli_timer_t *ti = &cli->timers.coap;

    /* Should be randomized. */
    ti->tout = (struct timeval){ .tv_sec = EC_COAP_RESP_TIMEOUT, .tv_usec = 0 };

    /* Create new CoAP (non persistent) timeout event for this client. */
    return ec_cli_timer_start(cli, ti, EC_COAP_MAX_RETRANSMIT, 
            ec_cli_coap_timeout);
}

int ec_cli_stop_coap_timer(ec_client_t *cli)
{
    dbg_return_if (cli == NULL, -1);

    ec_cli_timers_t *ti = &cli->timers;

    return ec_cli_timer_remove(&ti->coap);
}

int ec_cli_restart_coap_timer(ec_client_t *cli)
{
    dbg_return_if (cli == NULL, -1);

    ec_t *coap = cli->base;
    ec_cli_timer_t *ti = &cli->timers.coap;

    dbg_return_ifm (ti->retries_left == 0, -1, "CoAP timer exhausted");

    /* Double timeout value. */
    ti->tout.tv_sec *= 2;

    u_dbg("exp timeout = %ds", ti->tout.tv_sec);

    /* Decrement the retries left. */
    --ti->retries_left;

    /* Re-arm the CoAP timeout. */
    return ec_cli_timer_restart(ti);
}

int ec_cli_start_app_timer(ec_client_t *cli)
{
    dbg_return_if (cli == NULL, -1);

    ec_cli_timer_t *ti = &cli->timers.app;

    /* One-shot timer.  The timeout value has been already set, hence use
     * NULL here. */
    return ec_cli_timer_start(cli, ti, 1, ec_cli_app_timeout);
}

int ec_cli_stop_app_timer(ec_client_t *cli)
{
    dbg_return_if (cli == NULL, -1);

    ec_cli_timers_t *ti = &cli->timers;

    return ec_cli_timer_remove(&ti->app);
}

static void ec_cli_app_timeout(evutil_socket_t u0, short u1, void *c)
{
    ec_client_t *cli = (ec_client_t *) c;

    /* Set state to APP_TIMEOUT. */
    (void) ec_client_set_state(cli, EC_CLI_STATE_APP_TIMEOUT);

    return;
}

int ec_cli_start_obs_timer(ec_client_t *cli)
{
    ec_opts_t *opts;
    uint32_t max_age;

    dbg_return_if (cli == NULL, -1);

    ec_cli_timer_t *ti = &cli->timers.obs;

    ti->tout = (struct timeval){ .tv_sec = 0, .tv_usec = 0 };

    /* Use (implicit or explicit) Max-Age to feed the WAIT_NFY timeout. */
    if ((opts = ec_client_get_response_options(cli)) == NULL
            || ec_opts_get_max_age(opts, &max_age))
        ti->tout.tv_sec = EC_COAP_DEFAULT_MAX_AGE;
    else
        ti->tout.tv_sec = max_age;

    /* Add 1 sec of tolerance to accomodate network latency. */
    ti->tout.tv_sec += 1;

    /* One-shot timer. */
    return ec_cli_timer_start(cli, ti, 1, ec_cli_obs_timeout);
}

int ec_cli_stop_obs_timer(ec_client_t *cli)
{
    dbg_return_if (cli == NULL, -1);

    ec_cli_timers_t *ti = &cli->timers;

    return ec_cli_timer_remove(&ti->obs);
}

int ec_cli_restart_obs_timer(ec_client_t *cli)
{
    dbg_return_if (cli == NULL, -1);

    ec_cli_timers_t *ti = &cli->timers;

    return ec_cli_timer_restart(&ti->obs);
}

static void ec_cli_obs_timeout(evutil_socket_t u0, short u1, void *c)
{
    ec_client_t *cli = (ec_client_t *) c;

    /* Remove the observe flag from the client context. */
    cli->observe.on = false;

    /* Set state to OBS_TIMEOUT. */
    (void) ec_client_set_state(cli, EC_CLI_STATE_OBS_TIMEOUT);

    return;
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
    else if (state == EC_CLI_STATE_WAIT_NFY)
    {
        /* Start (or restart) timeout counter based on requested resource's 
         * max-age. */
        if (cur == EC_CLI_STATE_WAIT_NFY)
            dbg_err_if (ec_cli_restart_obs_timer(cli));
        else
        {
            /* In case we enter the WAIT_NFY through one of ACKD or SENT, stop 
             * any running application and/or retransmit timers, then start 
             * the observation timeout. */
            dbg_if (ec_cli_stop_app_timer(cli));
            dbg_if (is_con && ec_cli_stop_coap_timer(cli));
            dbg_err_if (ec_cli_start_obs_timer(cli));
        }
    }
    else if ((is_final_state = ec_client_state_is_final(state)))
    {
        /* Any final state MUST destroy all pending timers. */
        dbg_if (ec_cli_stop_app_timer(cli));

        /* If CON also stop the retransmission timer. */
        dbg_if (is_con && ec_cli_stop_coap_timer(cli));

        /* Tear down any observe timeout. */
        dbg_if (ec_cli_stop_obs_timer(cli));
    }

    /* Finally set state and, in case the state we've entered is final, or
     * we are (re)entering the WAIT_NFY state, invoke the user callback. */
    cli->state = state;

    if (is_final_state || cli->state == EC_CLI_STATE_WAIT_NFY)
        (void) ec_client_invoke_user_callback(cli);

    if (is_final_state)
        ec_client_free(cli); /* We can now finish off with this client. */

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
    dbg_err_ifm (t->l != flow->token_sz || memcmp(t->v, flow->token, t->l),
            "received token mismatch");

    /* Attach response code to the client context. */
    dbg_err_if (ec_flow_set_resp_code(flow, (ec_rc_t) h->code));

    /* Attach payload, if any, to the client context. */
    if ((plen = raw_sz - (olen + EC_COAP_HDR_SIZE)))
        (void) ec_pdu_set_payload(res, raw + EC_COAP_HDR_SIZE + olen, plen);

    /* TODO fill in the residual info (e.g. socket...). */

    /* Add response PDU to the client response set. */
    dbg_err_if (ec_res_set_add(&cli->res_set, res));
    res = NULL;

    /* Check if a (possibly) requested observation has been accepted by the
     * end node and set the client->obs flag in case.  Do this *after* 
     * the 'res' PDU is added to the response set in client context. */
    dbg_err_if (ec_client_handle_observation(cli));

    /* Just before invoking the client callback, set state to one of DONE or
     * WAIT_NFY (observer).  If state is final, make the caller aware of that 
     * through EC_NET_CBRC_DEAD which signals that the client context is not 
     * available anymore. */
    ec_cli_state_t next = cli->observe.on 
        ? EC_CLI_STATE_WAIT_NFY 
        : EC_CLI_STATE_REQ_DONE;

    if (ec_client_set_state(cli, next) == true)
        return EC_NET_CBRC_DEAD;    /* final */
    else
    {
        /* In case the client context holds an observation, cleanup the
         * response set so that it can be reused on next notification. */
        if (cli->observe.on)
            ec_res_set_clear(&cli->res_set);
        return EC_NET_CBRC_SUCCESS; /* non-final */
    }

cleanup:
    u_dbg("TODO check this cleanup: label");
    ec_pdu_free(res);
    return EC_NET_CBRC_SUCCESS;
err:
    if (res)
        ec_pdu_free(res);
    return EC_NET_CBRC_ERROR;
}

/* Decide if the .observe.on flag has to be asserted or not. */
/* TODO handle "ok", "generic error", "refused", "stale notification", and
 * TODO explicit "cancellation" states. */
static int ec_client_handle_observation(ec_client_t *cli)
{
    bool obs_ack;
    uint16_t o_cnt;
    ec_opt_t *req_obs;
    ec_opts_t *res_opts, *req_opts;

    dbg_return_if (cli == NULL, -1);

    dbg_err_if ((req_opts = ec_client_get_request_options(cli)) == NULL);
    dbg_err_if ((res_opts = ec_client_get_response_options(cli)) == NULL);

    /* Lookup the Observe options in both request and response. */
    req_obs = ec_opts_get(req_opts, EC_OPT_OBSERVE);
    obs_ack = ec_opts_get_observe(res_opts, &o_cnt) == 0 ? true : false;

    /* 
     * In case we get here on subsequent notifications, check consistency.
     */
    if (cli->observe.on)
    {
        /* XXX Is it correct to reset the observe flag here, or should we 
         * XXX return specific code to the caller so that more sophisticated
         * XXX actions can be taken accordingly ? */

        time_t now = time(NULL);

        /* 1) "If the server is unable to continue sending notifications using 
         *     this media type, it SHOULD send a 5.00 (Internal Server Error) 
         *     notification and MUST empty the list of observers of the 
         *     resource." */
        if (ec_response_get_code(cli) == EC_INTERNAL_SERVER_ERROR)
        {
            u_dbg("observation canceled by the server");

            cli->observe.on = false;
            return 0;
        }

        /* 2) "Each such notification response MUST include an Observe Option 
         *     and MUST echo the token specified by the client in the GET 
         *     request" */
        if (obs_ack == false)
        {
            u_dbg("Observe opt missing in notification !");

            cli->observe.on = false;
            return 0;
        }

        /* 3) Check stale notification. */
        if (((uint32_t) (cli->observe.last_cnt - o_cnt)) % (1 << 16) < (1 << 15)
                && now < cli->observe.last_ts + (1 << 14))
        {
            u_dbg("stale (or duplicate) notification (last=%u, curr=%u)",
                    cli->observe.last_cnt, o_cnt);
            goto err;
        }

        cli->observe.last_cnt = o_cnt;
        cli->observe.last_ts = now;

        return 0;
    }

    /* Try to see if we have asked for an Observe on the remote resource, and 
     * in case assert the .observe.on flag if the server has acknowledged. */
    cli->observe.on = (req_obs && obs_ack) ? true : false;

    return 0;
err:
    return -1;
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

void ec_res_set_clear(ec_res_set_t *rset)
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

static int ec_cli_obs_init(ec_cli_obs_t *obs)
{
    dbg_return_if (obs == NULL, -1);

    obs->on = false;
    obs->last_cnt = 0;
    obs->last_ts = 0;

    return 0;
}

