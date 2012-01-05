#include <u/libu.h>
#include "evcoap_srv.h"
#include "evcoap_base.h"
#include "evcoap_flow.h"

ec_server_t *ec_server_new(struct ec_s *coap, evutil_socket_t sd)
{
    ec_server_t *srv = NULL;

    dbg_err_sif ((srv = u_zalloc(sizeof *srv)) == NULL);

    return srv;
err:
    return NULL;
}

void ec_server_input(evutil_socket_t sd, short u, void *arg)
{
    ec_t *coap = (ec_t *) arg;

    u_unused_args(u);

    ec_net_dispatch(sd, ec_server_handle_pdu, coap);
}

/* TODO also supply the related ec_conn_t object. */
/* TODO factor out common code with ec_client_handle_pdu, namely the PDU 
 *      decoding */
int ec_server_handle_pdu(ev_uint8_t *raw, size_t raw_sz, void *arg)
{
    size_t olen = 0, plen;
    int TODO_sd = -1;
    ec_pdu_t *req = NULL;
    ec_server_t *srv = NULL;
    ec_t *coap;
    u_uri_t *url = NULL;

    dbg_return_if ((coap = (ec_t *) arg) == NULL, -1);
    dbg_return_if (raw == NULL, -1);
    dbg_return_if (!raw_sz, -1);

    /* Make room for the new PDU. */
    dbg_err_sif ((req = ec_pdu_new_empty()) == NULL);

    ec_hdr_t *h = &req->hdr_bits;    /* shortcut */

    /* Decode CoAP header. */
    dbg_err_if (ec_pdu_decode_header(req, raw, raw_sz));

    /* Avoid processing spurious stuff (i.e. responses in server context.) */
    dbg_err_ifm (h->code >= 64 && h->code <= 191, 
            "unexpected response code in server request context");

    /* TODO Check if it's a duplicate (mid and token). */

    /* If PDU is a request, create a new server context. */
    if (h->code)
        dbg_err_if ((srv = ec_server_new(coap, TODO_sd)) == NULL);
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

    /* Recompose the requested URI (assume NoSec is the sole supported mode.) */
    bool nosec = true;
    flow->uri = ec_opts_compose_url(&req->opts, &conn->us, nosec);
    dbg_err_if (flow->uri == NULL);

    /* Everything has gone smoothly, set state accordingly. */
    (void) ec_server_set_req(srv, req);
    ec_server_set_state(srv, EC_SRV_STATE_REQ_OK);

    /* TODO invoke callback registered for the requested URI (or fallback
     * TODO to generic URI handler if none matches.) */

    return 0;
err:
    ec_server_set_state(srv, EC_CLI_STATE_INTERNAL_ERR);
    return -1;
}

void ec_server_set_state(ec_server_t *srv, ec_srv_state_t state)
{
    /* TODO check valid transitions, timers, etc. */
    srv->state = state;

    return;
}
