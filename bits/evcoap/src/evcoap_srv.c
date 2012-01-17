#include <u/libu.h>
#include "evcoap_srv.h"
#include "evcoap_base.h"
#include "evcoap_flow.h"

static int ec_server_handle_pdu(ev_uint8_t *raw, size_t raw_sz, int sd,
        struct sockaddr_storage *peer, void *arg);

ec_server_t *ec_server_new(struct ec_s *coap, evutil_socket_t sd)
{
    ec_pdu_t *res = NULL;
    ec_server_t *srv = NULL;

    dbg_err_sif ((srv = u_zalloc(sizeof *srv)) == NULL);
    srv->base = coap;

    ec_flow_t *flow = &srv->flow;
    ec_conn_t *conn = &flow->conn;

    dbg_err_sif ((res = ec_pdu_new_empty()) == NULL);
    dbg_err_if (ec_pdu_set_flow(res, flow));

    /* Attach response PDU to the server context. */
    srv->res = res, res = NULL; /* ownership lost */

    return srv;
err:
    if (srv)
        ec_server_free(srv);
    if (res)
        ec_pdu_free(res);
    return NULL;
}

void ec_server_free(ec_server_t *srv)
{
    if (srv)
    {
        if (srv->res)
            ec_pdu_free(srv->res);
        if (srv->req)
            ec_pdu_free(srv->req);
        u_free(srv);
    }
}

void ec_server_input(evutil_socket_t sd, short u, void *arg)
{
    ec_t *coap = (ec_t *) arg;

    u_unused_args(u);

    ec_net_pullup_all(sd, ec_server_handle_pdu, coap);
}

/* TODO also supply the related ec_conn_t object. */
/* TODO factor out common code with ec_client_handle_pdu, namely the PDU 
 *      decoding */
static int ec_server_handle_pdu(ev_uint8_t *raw, size_t raw_sz, int sd,
        struct sockaddr_storage *peer, void *arg)
{
    ec_resource_t *r;
    size_t olen = 0, plen;
    int flags = 0;
    ec_pdu_t *req = NULL;
    ec_server_t *srv = NULL;
    ec_t *coap;
    u_uri_t *url = NULL;
    bool nosec = true;

    dbg_return_if ((coap = (ec_t *) arg) == NULL, -1);
    dbg_return_if (raw == NULL, -1);
    dbg_return_if (!raw_sz, -1);
    dbg_return_if (sd == -1, -1);
    dbg_return_if (peer == NULL, -1);

    /* Make room for the new PDU. */
    dbg_err_sif ((req = ec_pdu_new_empty()) == NULL);

    ec_hdr_t *h = &req->hdr_bits;    /* shortcut */

    /* Decode CoAP header. */
    dbg_err_if (ec_pdu_decode_header(req, raw, raw_sz));

    /* Avoid processing spurious stuff (i.e. responses in server context.) */
    dbg_err_ifm (h->code >= 64 && h->code <= 191, 
            "unexpected response code in server request context");

    /* Pass MID and peer address to the dup handler machinery. */
    ec_dups_t *dups = &coap->dups;

    /* TODO Check if it's a duplicate (mid and token). */
    switch (ec_dups_handle_incoming_climsg(dups, h->mid, sd, peer))
    {
        case 0:
            /* Not a duplicate, proceed with normal processing. */
            break;
        case 1:
            /* Duplicate, possible resending of the paired message is handled 
             * by ec_dups_handle_incoming_climsg(). */
            return 0;
        default:
            /* Internal error. */
            u_dbg("Duplicate handling machinery failed !");
            goto err;
    }

    /* If PDU is a request, create a new server context. */
    if (h->code)
    {
        dbg_err_if ((srv = ec_server_new(coap, sd)) == NULL);
        (void) ec_server_set_msg_model(srv, h->t == EC_CON ? true : false);
    }
    else
        u_dbg("TODO handle incoming RST and/or ACK");

    /* Decode options. */
    if (h->oc)
    {
        dbg_err_ifm (ec_opts_decode(&req->opts, raw, raw_sz, h->oc, &olen),
                "CoAP options could not be parsed correctly");
    }

    ec_flow_t *flow = &srv->flow;   /* shortcut */
    ec_conn_t *conn = &flow->conn;  /* ditto */

    /* Save token into context. */
    ec_opt_t *t = ec_opts_get(&req->opts, EC_OPT_TOKEN);
    dbg_err_if (ec_flow_save_token(flow, t ? t->v : NULL, t ? t->l : 0));

    /* Response payload has been allocated by ec_server_new(). */
    ec_pdu_t *res = srv->res;   /* shortcut */
    dbg_err_if (ec_pdu_set_sibling(res, req));

    /* Save dst and src addresses in srv context. */
    dbg_err_if (ec_net_save_us(conn, sd));
    dbg_err_if (ec_pdu_set_peer(res, peer));

    /* Recompose the requested URI and save it into the server context.
     * XXX Assume NoSec is the sole supported mode. */
    url = ec_opts_compose_url(&req->opts, &conn->us, nosec);
    dbg_err_if (ec_flow_save_url(flow, url));

    /* Everything has gone smoothly, so set state accordingly. */
    (void) ec_server_set_req(srv, req);
    ec_server_set_state(srv, EC_SRV_STATE_REQ_OK);

    /* Now it's time to invoke the callback registered for the requested URI,
     * or to fallback to generic URI handler if none matches. */
/* u_dbg("requested URI: %s", flow->urlstr); */

    TAILQ_FOREACH(r, &coap->resources, next)
    {
        if (strcasecmp(r->path, flow->urlstr))
            continue;

        /* Initialize the poll/wait timeout. */
        struct timeval tv = { .tv_sec = 0, .tv_usec = 0 };

        switch (r->cb(srv, r->cb_args, &tv, false))
        {
            case EC_CBRC_READY:
                dbg_err_if (ec_server_send_resp(srv));
                /* In case it is NON or CON piggybacked, we can set state 
                 * to RESP_DONE. */
                ec_server_set_state(srv, EC_SRV_STATE_RESP_DONE);
                break;
            case EC_CBRC_WAIT:
            case EC_CBRC_POLL:
                u_dbg("TODO handle client wait/poll");
                break;
            case EC_CBRC_ERROR:
                /* This gets mapped to an internal error. */
                goto err;
            default:
                dbg_err("unknown return code from client callback !");
        }

        return 0;
    }

    /* Fall back to catch-all function, if set. */
    if (coap->fb)
    {
        /* TODO handle return code. */
        switch (coap->fb(srv, coap->fb_args, NULL, false))
        {
            case EC_CBRC_READY:
            case EC_CBRC_WAIT:
            case EC_CBRC_POLL:
            case EC_CBRC_ERROR:
            default:
                break;
        }
    }

    return 0;
err:
    if (url)
        u_uri_free(url);
    ec_server_set_state(srv, EC_CLI_STATE_INTERNAL_ERR);
    return -1;
}

struct ec_s *ec_server_get_base(ec_server_t *srv)
{
    dbg_return_if (srv == NULL, NULL);

    return srv->base;
}

int ec_server_set_req(ec_server_t *srv, ec_pdu_t *req)
{
    dbg_return_if (srv == NULL, -1);
    dbg_return_if (req == NULL, -1);

    srv->req = req;

    return 0;
}

void ec_server_set_state(ec_server_t *srv, ec_srv_state_t state)
{
    u_dbg("%s: TODO check valid transitions, timers, etc.", __func__);

    srv->state = state;

    return;
}

int ec_server_send_resp(ec_server_t *srv)
{
    bool is_con;

    dbg_return_if (srv == NULL, -1);

    /* Consistency check:
     * - response code
     * - payload in case response code is Content
     * - ...
     */
    ec_flow_t *flow = &srv->flow;   /* shortcut */
    dbg_err_if (!EC_IS_RESP_CODE(flow->resp_code));

    /* Need a payload in case response code is 2.05 Content. */
    ec_pdu_t *res = srv->res;       /* shortcut */
    dbg_err_if (flow->resp_code == EC_CONTENT && res->payload == NULL);

    ec_conn_t *conn = &flow->conn;  /* shortcut */
    dbg_err_if (ec_net_get_confirmable(conn, &is_con));

    /* Encode, in case it was not already ACK'd, use piggyback. */
    if (is_con && srv->state != EC_SRV_STATE_ACK_SENT)
        dbg_err_if (ec_pdu_encode_response_piggyback(res));
    else
        dbg_err_if (ec_pdu_encode_response_separate(res));

    /* Send response PDU. */
    dbg_err_if (ec_pdu_send(res));

    return 0;
err:
    return -1;
}

const char *ec_server_get_url(ec_server_t *srv)
{
    dbg_return_if (srv == NULL, NULL);

    return ec_flow_get_urlstr(&srv->flow);
}

int ec_server_set_msg_model(ec_server_t *srv, bool is_con)
{
    dbg_return_if (srv == NULL, -1);

    return ec_net_set_confirmable(&srv->flow.conn, is_con);
}
