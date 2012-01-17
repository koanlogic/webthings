#include <u/libu.h>
#include <event2/util.h>
#include "evcoap_pdu.h"

static int encode_response(ec_pdu_t *pdu, ev_uint8_t t, ec_rc_t rc,
        ev_uint16_t mid);
static void encode_header(ec_pdu_t *pdu, ev_uint8_t code, ev_uint8_t t,
        ev_uint16_t mid);

int ec_pdu_set_payload(ec_pdu_t *pdu, ev_uint8_t *payload, size_t sz)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (payload == NULL, -1);
    dbg_return_if (sz == 0, -1);

    dbg_return_sif ((pdu->payload = u_memdup(payload, sz)) == NULL, -1);
    pdu->payload_sz = sz;

    return 0;
}

int ec_pdu_set_flow(ec_pdu_t *pdu, ec_flow_t *flow)
{
    dbg_return_if (pdu == NULL, -1);

    pdu->flow = flow;

    return 0;
}

int ec_pdu_set_peer(ec_pdu_t *pdu, const struct sockaddr_storage *peer)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (peer == NULL, -1);

    memcpy(&pdu->peer, peer, peer->ss_len);

    return 0;
}

int ec_pdu_set_sibling(ec_pdu_t *pdu, ec_pdu_t *sibling)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (sibling == NULL, -1);
    dbg_return_if (pdu->sibling != NULL, -1);

    pdu->sibling = sibling;

    return 0;
}

int ec_pdu_init_options(ec_pdu_t *pdu)
{
    dbg_return_if (pdu == NULL, -1);

    TAILQ_INIT(&pdu->opts.bundle);
    pdu->opts.noptions = 0;

    return 0;
}

int ec_pdu_send(ec_pdu_t *pdu)
{
    dbg_return_if (pdu == NULL, -1);

    ec_opts_t *opts = &pdu->opts;           /* shortcut */
    ec_conn_t *conn = &pdu->flow->conn;     /* ditto */

    return ec_net_send(pdu->hdr, opts->enc, opts->enc_sz, pdu->payload,
            pdu->payload_sz, conn->socket, &pdu->peer);
}

int ec_pdu_encode_response_piggyback(ec_pdu_t *pdu)
{
    dbg_return_if (pdu == NULL, -1);

    /* Expect user has set a response code. */
    ec_flow_t *flow = pdu->flow;
    dbg_return_if (!EC_IS_RESP_CODE(flow->resp_code), -1);

    /* Mirror the same MID as in request PDU. */
    ec_pdu_t *sibling = pdu->sibling;
    dbg_return_if (sibling == NULL, -1);

    /* E.g. T=ACK, Code=69, MID=0x7d37. */
    return encode_response(pdu, EC_COAP_ACK, flow->resp_code, sibling->mid);
}

int ec_pdu_encode_response_ack(ec_pdu_t *pdu)
{
    dbg_return_if (pdu == NULL, -1);

    /* Mirror the same MID as in request PDU. */
    ec_pdu_t *sibling = pdu->sibling;
    dbg_return_if (sibling == NULL, -1);

    /* E.g. T=ACK, Code=0, MID=0x7d38. */
    return encode_response(pdu, EC_COAP_ACK, EC_RC_UNSET, sibling->mid);
}

int ec_pdu_encode_response_rst(ec_pdu_t *pdu)
{
    dbg_return_if (pdu == NULL, -1);

    /* Mirror the same MID as in request PDU. */
    ec_pdu_t *sibling = pdu->sibling;
    dbg_return_if (sibling == NULL, -1);

    /* E.g. T=ACK, Code=0, MID=0x7d38. */
    return encode_response(pdu, EC_COAP_RST, EC_RC_UNSET, sibling->mid);
}

int ec_pdu_encode_response_separate(ec_pdu_t *pdu)
{
    bool is_con;
    ev_uint16_t mid;

    dbg_return_if (pdu == NULL, -1);

    /* Create new MID */
    evutil_secure_rng_get_bytes(&mid, sizeof mid);

    /* Get requested messaging semantics. */
    ec_flow_t *flow = pdu->flow;
    dbg_return_if (ec_net_get_confirmable(&flow->conn, &is_con), -1);

    /* E.g. T=CON|NON, Code=69, MID=0x7d38. */
    return encode_response(pdu, is_con ? EC_COAP_CON : EC_COAP_NON, 
            flow->resp_code, mid);
}

static int encode_response(ec_pdu_t *pdu, ev_uint8_t t, ec_rc_t rc,
        ev_uint16_t mid)
{
    /* Dare the incredible: trust the caller :-) */

    /* Add token. */
    ec_flow_t *flow = pdu->flow;
    ec_opts_t *opts = &pdu->opts;

    /* TODO Check that no token has been set in options. */
    if (flow->token_sz)
        dbg_err_if (ec_opts_add_token(opts, flow->token, flow->token_sz));

    /* Encode options.  This is needed before header encoding because it sets
     * the 'oc' field. */
    dbg_err_if (ec_opts_encode(&pdu->opts));

    /* Encode header. */
    encode_header(pdu, rc, t, mid);

    return 0;
err:
    return -1;
}

int ec_pdu_encode_request(ec_pdu_t *pdu)
{
    dbg_return_if (pdu == NULL, -1);

    u_dbg("TODO %s", __func__);

#if 0
    ec_flow_t *flow = pdu->flow;
    ec_hdr_t *h = &pdu->hdr_bits;

    if (!h->mid)
        evutil_secure_rng_get_bytes(&h->mid, sizeof h->mid);

    /* Encode options.  This is needed before header encoding because it sets
     * the 'oc' field. */
    dbg_err_if (ec_opts_encode(&pdu->opts));

    /* Encode header. */
    if (flow->method != EC_METHOD_UNSET)
        dbg_err_if (encode_req_header(pdu));
    else if (flow->resp_code != EC_RC_UNSET)
        dbg_err_if (encode_res_header(pdu));
    else
        dbg_err("WTF ?");

    return 0;
err:
#endif
    return -1;
}

int ec_pdu_decode_header(ec_pdu_t *pdu, const ev_uint8_t *raw, size_t raw_sz)
{
    ev_uint8_t ver;

    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (raw == NULL, -1);

    dbg_return_ifm (raw_sz < EC_COAP_HDR_SIZE, -1,
            "not enough bytes to hold a CoAP header");

    dbg_err_ifm ((ver = (raw[0] & 0xc0) >> 6) != EC_COAP_VERSION_1,
            "unsupported CoAP version %u", ver);

    ec_hdr_t *h = &pdu->hdr_bits;

    h->t = (raw[0] & 0x30) >> 4;
    h->oc = raw[0] & 0x0f;
    h->code = raw[1];
    h->mid = ntohs((raw[2] << 8) | raw[3]);

    /* Make a copy of the raw bytes. */
    memcpy(&pdu->hdr, raw, EC_COAP_HDR_SIZE);

    return 0;
err:
    return -1;
}

static void encode_header(ec_pdu_t *pdu, ev_uint8_t code, ev_uint8_t t,
        ev_uint16_t mid)
{
    ev_uint8_t ver = EC_COAP_VERSION_1, oc = pdu->opts.noptions;

    pdu->hdr[0] = ((ver & 0x03) << 6) | ((t & 0x03) << 4) | (oc & 0x0f);
    pdu->hdr[1] = code;
    pdu->hdr[2] = (htons(mid) & 0xff00) >> 8;
    pdu->hdr[3] = htons(mid) & 0x00ff;

    return;
}

ec_pdu_t *ec_pdu_new_empty(void)
{
    ec_pdu_t *pdu = NULL;

    dbg_err_sif ((pdu = u_zalloc(sizeof *pdu)) == NULL);

    (void) ec_pdu_init_options(pdu);

    return pdu;
err:
    return NULL;
}

void ec_pdu_free(ec_pdu_t *pdu)
{
    if (pdu)
    {
        ec_opts_clean(&pdu->opts);
        u_free(pdu->payload);
        u_free(pdu);
    }
}

int ec_pdu_get_type(ec_pdu_t *pdu, ev_uint8_t *t)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (t == NULL, -1);

    /* XXX Check that header has been decoded. */

    *t = pdu->hdr_bits.t;

    return 0;
}

int ec_pdu_get_mid(ec_pdu_t *pdu, ev_uint16_t *mid)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (mid == NULL, -1);

    /* XXX Check that header has been decoded. */

    *mid = pdu->hdr_bits.mid;

    return 0;
}


