#include <u/libu.h>
#include <event2/util.h>
#include "evcoap_pdu.h"

static void encode_header(ec_pdu_t *pdu, ev_uint8_t code, ev_uint8_t t);
static void encode_req_header(ec_pdu_t *pdu);
static void encode_res_header(ec_pdu_t *pdu);

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

int ec_pdu_init_options(ec_pdu_t *pdu)
{
    dbg_return_if (pdu == NULL, -1);

    TAILQ_INIT(&pdu->opts.bundle);
    pdu->opts.noptions = 0;

    return 0;
}

int ec_pdu_send(ec_pdu_t *pdu, struct sockaddr_storage *d, ev_socklen_t d_sz)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (pdu->hdr == NULL, -1);
    dbg_return_if (d == NULL, -1);
    dbg_return_if (d_sz == 0, -1);

    ec_opts_t *opts = &pdu->opts;           /* shortcut */
    ec_conn_t *conn = &pdu->flow->conn;     /* ditto */

    return ec_net_send(pdu->hdr, opts->enc, opts->enc_sz, pdu->payload,
            pdu->payload_sz, conn->socket, d, d_sz);
}

int ec_pdu_encode(ec_pdu_t *pdu)
{
    dbg_return_if (pdu == NULL, -1);

    ec_flow_t *flow = pdu->flow;
    ec_hdr_t *h = &pdu->hdr_bits;

    if (!h->mid)
        evutil_secure_rng_get_bytes(&h->mid, sizeof h->mid);

    /* Encode options.  This is needed before header encoding because it sets
     * the 'oc' field. */
    dbg_err_if (ec_opts_encode(&pdu->opts));

    /* Encode header. */
    if (flow->method != EC_METHOD_UNSET)
        encode_req_header(pdu);
    else if (flow->resp_code != EC_RC_UNSET)
        encode_res_header(pdu);
    else
        dbg_err("WTF ?");

    return 0;
err:
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

    /* TODO some generic consistency check ? */

    return 0;
err:
    return -1;
}

static void encode_req_header(ec_pdu_t *pdu)
{
    ev_uint8_t t = pdu->flow->conn.is_confirmable ? EC_COAP_CON : EC_COAP_NON;

    encode_header(pdu, pdu->flow->method, t);
}

static void encode_res_header(ec_pdu_t *pdu)
{
    ev_uint8_t t = pdu->flow->conn.is_confirmable ? EC_COAP_CON : EC_COAP_NON;

    encode_header(pdu, pdu->flow->resp_code, t);
}

static void encode_header(ec_pdu_t *pdu, ev_uint8_t code, ev_uint8_t t)
{
    ev_uint16_t mid = pdu->hdr_bits.mid;
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
