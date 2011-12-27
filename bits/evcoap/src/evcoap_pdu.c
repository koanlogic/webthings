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

int ec_pdu_send(ec_pdu_t *pdu, struct sockaddr_storage *dest)
{
    struct msghdr msg;
    struct iovec iov[3];
    size_t iov_idx = 0;

    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (pdu->hdr == NULL, -1);
    dbg_return_if (dest == NULL, -1);

    /* Header is non optional. */
    iov[iov_idx].iov_base = (void *) pdu->hdr;
    iov[iov_idx].iov_len = 4;
    ++iov_idx;

    ec_opts_t *opts = &pdu->opts;

    /* Add options, if any. */
    if (opts->enc && opts->enc_sz)
    {
        iov[iov_idx].iov_base = (void *) opts->enc;
        iov[iov_idx].iov_len = opts->enc_sz;
        ++iov_idx;
    }
    
    /* Add payload, if any. */
    if (pdu->payload && pdu->payload_sz)
    {
        iov[iov_idx].iov_base = (void *) pdu->payload;
        iov[iov_idx].iov_len = pdu->payload_sz;
        ++iov_idx;
    }

    msg.msg_name = (void *) dest;
    msg.msg_namelen = dest->ss_len;
    msg.msg_iov = iov;
    msg.msg_iovlen = iov_idx;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    ec_conn_t *conn = &pdu->flow->conn;

    dbg_err_sif (sendmsg(conn->socket, &msg, 0) == -1);

    return 0;
err:
    return -1;
}

int ec_pdu_encode(ec_pdu_t *pdu)
{
    dbg_return_if (pdu == NULL, -1);

    ec_flow_t *flow = pdu->flow;

    if (!pdu->mid)
        evutil_secure_rng_get_bytes(&pdu->mid, sizeof pdu->mid);

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
    ev_uint16_t mid = pdu->mid;
    ev_uint8_t ver = EC_COAP_VERSION_1, oc = pdu->opts.noptions;

    pdu->hdr[0] = ((ver & 0x03) << 6) | ((t & 0x03) << 4) | (oc & 0x0f);
    pdu->hdr[1] = code;
    pdu->hdr[2] = (htons(mid) & 0xff00) >> 8;
    pdu->hdr[3] = htons(mid) & 0x00ff;
}

