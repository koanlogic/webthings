#include <event2/event.h>
#include <event2/util.h>
#include <u/libu.h>
#include "evcoap_cli.h"
#include "evcoap_base.h"
#include "evcoap_debug.h"

#define EMPTY_STRING(s)  ((s) == NULL || *(s) == '\0')

static void ec_client_dns_cb(int result, struct evutil_addrinfo *res, void *a);

int ec_client_set_method(ec_client_t *cli, ec_method_t m)
{
    ec_flow_t *flow = &cli->flow;

    dbg_return_if (m < EC_GET || m > EC_DELETE, -1);

    flow->method = m;

    return 0;
}

int ec_client_set_proxy(ec_client_t *cli, const char *host, ev_uint16_t port)
{
    ec_conn_t *conn = &cli->flow.conn;

    dbg_return_if (EMPTY_STRING(host), -1);

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
            dbg_err_if (ec_opts_add_uri_port(opts, (ev_uint16_t) port));
        }

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

        if ((p = u_uri_get_query(u)) && *p != '\0')
            dbg_err_if (ec_opts_add_uri_query(opts, p));
    }

    return 0;
err:
    return -1;
}

void ec_client_free(ec_client_t *cli)
{
    if (cli)
    {
        ec_flow_t *flow = &cli->flow;
        ec_conn_t *conn = &flow->conn;

        /* Close socket. */
        evutil_closesocket(conn->socket);

        /* Free URI. */
        u_uri_free(flow->uri);

        /* TODO free cli->req */
        /* TODO free cli->res */
        /* TODO Destroy any associated timer ? */

        u_free(cli);
    }

    return;
}

int ec_client_set_msg_model(ec_client_t *cli, bool is_con)
{
    cli->flow.conn.is_confirmable = is_con;
    return 0;
}

ec_client_t *ec_client_new(struct ec_s *coap, ec_method_t m, const char *uri, 
        ec_msg_model_t mm, const char *proxy_host, ev_uint16_t proxy_port)
{
    ec_client_t *cli = NULL;

    dbg_return_if (coap == NULL, NULL);
    /* Assume all other input parameters are checked by called functions. */

    dbg_err_sif ((cli = u_zalloc(sizeof *cli)) == NULL);

    /* Must be done first because the following URI validation (namely the
     * scheme compliance test) depends on the fact that this request is 
     * expected to go through a proxy or not. */
    if (proxy_host)
        dbg_err_if (ec_client_set_proxy(cli, proxy_host, proxy_port));

    dbg_err_if (ec_pdu_init_options(&cli->req));
    dbg_err_if (ec_client_set_method(cli, m));
    dbg_err_if (ec_client_set_uri(cli, uri));
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
    ev_uint8_t tok[8];
    ec_opt_t *pu = NULL;
    const char *host;
    ev_uint16_t port;
    char sport[16];
    struct evutil_addrinfo hints;

    dbg_return_if (cli == NULL, -1);

    /* Expect client with state NONE.  Otherwise we jump to err where the 
     * state is set to INTERNAL_ERR. */
    dbg_err_ifm (cli->state != EC_CLI_STATE_NONE,
            "unexpected state %u", cli->state);

    req = &cli->req;
    flow = &cli->flow;
    conn = &flow->conn;

    /* TODO Sanitize request. */ 

    /* Add token option if missing. */
    if (!ec_opts_get(&req->opts, EC_OPT_TOKEN))
    {
        evutil_secure_rng_get_bytes(tok, sizeof tok);
        dbg_err_if (ec_opts_add_token(&req->opts, tok, sizeof tok));
    }

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

    cli->cb = cb;
    cli->cb_args = cb_args;

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
    ec_client_set_state(cli, EC_CLI_STATE_INTERNAL_ERR);
    return -1;
}

static void ec_client_dns_cb(int result, struct evutil_addrinfo *res, void *a)
{
    struct evutil_addrinfo *ai;
    ec_client_t *cli = (ec_client_t *) a;
    ec_pdu_t *req = &cli->req;
    ec_conn_t *conn = &cli->flow.conn;

#define EC_CLI_ASSERT(e, state)                 \
    do {                                        \
        if ((e))                                \
        {                                       \
            ec_client_set_state(cli, state);    \
            goto err;                           \
        }                                       \
    } while (0)

    /* Unset the evdns_getaddrinfo_request pointer, since when we get called
     * its lifetime is complete. */
    cli->dns_req = NULL;

    EC_CLI_ASSERT(result != DNS_ERR_NONE, EC_CLI_STATE_DNS_FAILED);

    ec_client_set_state(cli, EC_CLI_STATE_DNS_OK);

    /* Encode options and header. */
    EC_CLI_ASSERT(ec_pdu_encode(req), EC_CLI_STATE_INTERNAL_ERR);

    for (conn->socket = -1, ai = res; ai != NULL; ai = ai->ai_next)
    {
        conn->socket = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

        if (conn->socket == -1)
           continue;

        /* Send the request PDU. */
        if (ec_pdu_send(req, (struct sockaddr_storage *) ai->ai_addr,
                    ai->ai_addrlen))
        {
            /* Mark this socket as failed and try again. */
            evutil_closesocket(conn->socket), conn->socket = -1;
            continue;
        }

        EC_CLI_ASSERT(evutil_make_socket_nonblocking(conn->socket),
                EC_CLI_STATE_INTERNAL_ERR);

        ec_client_set_state(cli, EC_CLI_STATE_REQ_SENT);
        break;
    }

    /* Check whether the request PDU was actually sent out on any socket. */
    EC_CLI_ASSERT(conn->socket == -1, EC_CLI_STATE_INTERNAL_ERR);

    /* Add this to the pending clients' list. */
    EC_CLI_ASSERT(ec_client_register(cli), EC_CLI_STATE_INTERNAL_ERR);

    /* TODO add to the duplicate machinery */

    return;
err:
    return;
    /* TODO Invoke user callback with the failure code. */
}
#undef EC_CLI_ASSERT

void ec_client_set_state(ec_client_t *cli, ec_cli_state_t state)
{
    ec_cli_state_t cur = cli->state;

    u_dbg("[client=%p] transition request from '%s' to '%s'",
            cli, ec_cli_state_str(cur), ec_cli_state_str(state));

    /* Check that the requested state transition is valid.  Panic in case an 
     * invalid transition was requested. */
    switch (state)
    {
        case EC_CLI_STATE_INTERNAL_ERR:
            break;

        case EC_CLI_STATE_DNS_FAILED:
        case EC_CLI_STATE_DNS_OK:
            die_if (cur != EC_CLI_STATE_NONE);
            break;

        case EC_CLI_STATE_SEND_FAILED:
        case EC_CLI_STATE_REQ_SENT:
            die_if (cur != EC_CLI_STATE_DNS_OK
                    && cur != EC_CLI_STATE_COAP_RETRY);
            break;

        case EC_CLI_STATE_REQ_ACKD:
        case EC_CLI_STATE_COAP_RETRY:
        case EC_CLI_STATE_COAP_TIMEOUT:
            die_if (cur != EC_CLI_STATE_REQ_SENT);
            break;

        case EC_CLI_STATE_APP_TIMEOUT:
        case EC_CLI_STATE_REQ_DONE:
        case EC_CLI_STATE_REQ_RST:
            die_if (cur != EC_CLI_STATE_REQ_SENT
                    && cur != EC_CLI_STATE_REQ_ACKD);
            break;

        case EC_CLI_STATE_NONE:
        default:
            die(EXIT_FAILURE, "transaction cannot be set to state %u", state);
    }

    /* TODO handle timers and stuff... */

    cli->state = state;

    return;
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

int ec_client_handle_pdu(ev_uint8_t *raw, size_t raw_sz, void *arg)
{
    ec_client_t *cli = (ec_client_t *) arg;
    size_t olen = 0, plen;
    ev_uint8_t ver, t, oc, code;
    ev_uint16_t mid;
    ec_pdu_t *res = NULL;

    dbg_return_ifm (raw_sz < EC_COAP_HDR_SIZE, -1, 
            "not enough bytes to hold a CoAP header");

    /* Decode header. */
    ver = (raw[0] & 0xc0) >> 6;
    t = (raw[0] & 0x30) >> 4;
    oc = raw[0] & 0x0f;
    code = raw[1];
    mid = ntohs((raw[2] << 8) | raw[3]);

    /* Consistency checks. */

    dbg_err_ifm (ver != EC_COAP_VERSION_1,
            "unsupported CoAP version %u", ver);

    dbg_err_ifm (code >= 1 && code <= 31, 
            "unexpected request code in client response context");

    /*
     * TODO pass mid and source to the dup handler machinery... 
     */
    
    /* Handle empty responses (i.e. resets and separated acknowledgements)
     * specially. */
    if (!code)
        return ec_client_handle_empty_pdu(cli, t, mid);

    dbg_err_sif ((res = ec_pdu_new_empty()) == NULL);

    /* Parse options, if any. */
    dbg_err_ifm (oc && ec_opts_decode(&res->opts, raw, raw_sz, oc, &olen),
            "could not parse options");

    /* Attach payload, if any. */
    if ((plen = raw_sz - (olen + EC_COAP_HDR_SIZE)))
        (void) ec_pdu_set_payload(res, raw + EC_COAP_HDR_SIZE + olen, plen);

    /* TODO fill in the residual info (e.g. socket...). */

    /* Just before invoking the client callback, set state to DONE. */
    ec_client_set_state(cli, EC_CLI_STATE_REQ_DONE);

    /* Invoke the client callback */
    if (cli->cb)
        cli->cb(cli);
    else
    {
        /* TODO respond something standard in case there's no callback. */
    }

    return 0;
err:
    return -1;
}

int ec_client_handle_empty_pdu(ec_client_t *cli, ev_uint8_t t, ev_uint16_t mid)
{
    /* TODO */
    return 0;
}

/* Just a wrapper around ec_net_dispatch(). */
void ec_client_input(evutil_socket_t sd, short u, void *arg)
{
    ec_client_t *cli = (ec_client_t *) arg;

    u_unused_args(u);

    ec_net_dispatch(sd, ec_client_handle_pdu, cli);
}

void *ec_client_get_args(ec_client_t *cli)
{
    dbg_return_if (cli == NULL, NULL);

    return cli->cb_args;
}
