#include <u/libu.h>
#include <event2/util.h>
#include "evcoap_pdu.h"
#include "evcoap_base.h"

static int encode_response(ec_pdu_t *pdu, uint8_t t, ec_rc_t rc,
        uint16_t mid);
static void encode_header(ec_pdu_t *pdu, uint8_t code, uint8_t t,
        uint16_t mid);

int ec_pdu_set_payload(ec_pdu_t *pdu, uint8_t *payload, size_t sz)
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
    uint8_t peer_len;
    struct sockaddr_storage *loc;

    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (peer == NULL, -1);

    ec_flow_t *flow = pdu->flow;
    ec_conn_t *conn = &flow->conn;

    dbg_err_if (ec_net_socklen(peer, &peer_len));

    /* If the peer responded to a multicast request, it is saved in the
     * supplied PDU, otherwise it is set in attached (global) conn. */
    loc = conn->is_multicast ? &pdu->peer : &conn->peer;
    memcpy(loc, peer, peer_len);

    return 0;
err:
    return -1;
}

struct sockaddr_storage *ec_pdu_get_peer(ec_pdu_t *pdu)
{
    /* Trust the caller. */

    ec_flow_t *flow = pdu->flow;
    ec_conn_t *conn = &flow->conn;

    return conn->is_multicast ? &pdu->peer : &conn->peer;
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

    return ec_opts_init(&pdu->opts);
}

/* If 'dups' == NULL, don't go through the cache. */
int ec_pdu_send(ec_pdu_t *pdu, struct ec_dups_s *dups)
{
    int rc;
    ec_recvd_pdu_t *rpdu;

    dbg_return_if (pdu == NULL, -1);

    ec_opts_t *opts = &pdu->opts;           /* shortcut */
    ec_conn_t *conn = &pdu->flow->conn;     /* ditto */

    /* Send PDU to destination. */
    rc = ec_net_send(pdu->hdr, opts->enc, opts->enc_sz, pdu->payload,
            pdu->payload_sz, conn->socket, ec_pdu_get_peer(pdu));

    /* Independently of success of previous operations, save the
     * PDU into the duplicate handling mechanism, if appropriate and
     * requested by the caller.
     * The "if PDU has sibling" condition equals the fact that this
     * send has been elicited by an incoming message (the sibling PDU)
     * whose MID is used to locate the corresponding recvd_pdu. */
    if (dups && pdu->sibling)
    {
        /* Retrieve cache entry. */
        dbg_err_ifm ((rpdu = ec_dups_search(dups, EC_PDU_MID(pdu->sibling),
                        ec_pdu_get_peer(pdu))) == NULL, 
                "could not find received PDU with MID %u", 
                EC_PDU_MID(pdu->sibling));
    
        /* Update cache with supplied PDU pieces. */
        dbg_err_if (ec_recvd_pdu_update(rpdu, pdu->hdr, opts->enc, opts->enc_sz,
                    pdu->payload, pdu->payload_sz));
    }
    
    /* Fall through. */
err:
    return rc;
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
    return encode_response(pdu, EC_COAP_ACK, flow->resp_code,
            EC_PDU_MID(sibling));
}

int ec_pdu_encode_response_ack(ec_pdu_t *pdu)
{
    dbg_return_if (pdu == NULL, -1);

    /* Mirror the same MID as in request PDU. */
    ec_pdu_t *sibling = pdu->sibling;
    dbg_return_if (sibling == NULL, -1);

    /* E.g. T=ACK, Code=0, MID=0x7d38. */
    return encode_response(pdu, EC_COAP_ACK, EC_RC_UNSET, EC_PDU_MID(sibling));
}

int ec_pdu_encode_response_rst(ec_pdu_t *pdu)
{
    dbg_return_if (pdu == NULL, -1);

    /* Mirror the same MID as in request PDU. */
    ec_pdu_t *sibling = pdu->sibling;
    dbg_return_if (sibling == NULL, -1);

    /* E.g. T=ACK, Code=0, MID=0x7d38. */
    return encode_response(pdu, EC_COAP_RST, EC_RC_UNSET, EC_PDU_MID(sibling));
}

int ec_pdu_encode_response_separate(ec_pdu_t *pdu)
{
    bool is_con;
    uint16_t mid;

    dbg_return_if (pdu == NULL, -1);

    ec_hdr_t *h = &pdu->hdr_bits;

    /* Create new MID */
    if (!h->mid)
        evutil_secure_rng_get_bytes(&mid, sizeof mid);

    /* Get requested messaging semantics. */
    ec_flow_t *flow = pdu->flow;
    dbg_return_if (ec_net_get_confirmable(&flow->conn, &is_con), -1);

    /* Set reponse code. */

    /* E.g. T=CON|NON, Code=69, MID=0x7d38. */
    return encode_response(pdu, is_con ? EC_COAP_CON : EC_COAP_NON, 
            flow->resp_code, mid);
}

static int encode_response(ec_pdu_t *pdu, uint8_t t, ec_rc_t rc,
        uint16_t mid)
{
    /* Dare the incredible: trust the caller :-) */

    /* Add token. */
    ec_flow_t *flow = pdu->flow;
    ec_opts_t *opts = &pdu->opts;

    if (t != EC_COAP_RST && t != EC_COAP_CON && rc != EC_RC_UNSET)
    {
        /* TODO Check that no token has been set in options. */
        if (flow->token_sz)
            dbg_err_if (ec_opts_add_token(opts, flow->token, flow->token_sz));

        /* Encode options.  This is needed before header encoding because it 
         * sets the 'oc' field. */
        dbg_err_if (ec_opts_encode(&pdu->opts));
    }

    /* Encode header. */
    encode_header(pdu, rc, t, mid);

    return 0;
err:
    return -1;
}

int ec_pdu_encode_request(ec_pdu_t *pdu)
{
    bool is_con;
    uint16_t mid;

    dbg_return_if (pdu == NULL, -1);

    ec_hdr_t *h = &pdu->hdr_bits;

    /* Create new MID. */
    evutil_secure_rng_get_bytes(&mid, sizeof mid);

    /* Encode options.
     * Assume that the token has been already set by ec_client_go(). */
    dbg_err_if (ec_opts_encode(&pdu->opts));

    /* Get requested messaging semantics. */
    ec_flow_t *flow = pdu->flow;
    dbg_return_if (ec_net_get_confirmable(&flow->conn, &is_con), -1);

    /* E.g. T=CON|NON, Code=1, MID=0x7d38. */
    encode_header(pdu, flow->method, is_con ? EC_COAP_CON : EC_COAP_NON, mid);

    return 0; 
err:
    return -1;
}

int ec_pdu_decode_header(ec_pdu_t *pdu, const uint8_t *raw, size_t raw_sz)
{
    uint8_t ver;

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

static void encode_header(ec_pdu_t *pdu, uint8_t code, uint8_t t,
        uint16_t mid)
{
    uint8_t ver = EC_COAP_VERSION_1, oc = pdu->opts.noptions;

    pdu->hdr[0] = ((ver & 0x03) << 6) | ((t & 0x03) << 4) | (oc & 0x0f);
    pdu->hdr[1] = code;
    pdu->hdr[2] = (htons(mid) & 0xff00) >> 8;
    pdu->hdr[3] = htons(mid) & 0x00ff;

    return;
}

static const char *wrap_null_str(char *buf, size_t buf_sz, const char *prefix,
        const char *strfunc(int c), int c)
{
    const char *s;

    /* If string is not NULL simply return it. */
    s = strfunc(c);
    if (s)
        return s;

    /* Otherwise return buf with a string-representation of the code. */
    u_snprintf(buf, sizeof buf, "%s%d", prefix, c);
    u_warn("BUF: %s", buf);
    return buf;
}

void ec_pdu_dump(ec_pdu_t *pdu, bool srv)
{
#define FWRITE_STR(f, str) (fwrite(str, strlen(str), 1, f) < 1)
#define FWRITE_PRINT(f, ...) do { \
        dbg_err_if (u_snprintf(_buf, sizeof _buf, __VA_ARGS__)); \
        dbg_err_if (FWRITE_STR(f, _buf)); \
    } while (0);
#define FWRITE_HEX(f, b, sz) do { \
        FWRITE_PRINT(f, "0x"); \
        for (_bi = 0; _bi < sz; _bi++) \
            FWRITE_PRINT(f, "%02x", b[_bi]); \
    } while (0);

    enum { MAX_STR = 256 };
    FILE *f = NULL;
    char fname[U_PATH_MAX];
    const char *prefix = ".";
    char _buf[MAX_STR];
    char buf[MAX_STR];
    static int pnum = 1;
    ec_hdr_t *h;
    ec_opt_t *o;
    uint8_t _bi;

    dbg_ifb (pdu == NULL || pdu->hdr == NULL)
        return;

    h = &pdu->hdr_bits;

    dbg_err_if (u_snprintf(fname, sizeof fname, "%s/%d-%s.dump", prefix,
                pnum++, srv ? "srv" : "cli"));

    f = fopen(fname, "w+");
    dbg_err_sif (f == NULL);

    FWRITE_STR(f, "\n");
    FWRITE_STR(f, "[Header]: ");
    FWRITE_HEX(f, pdu->hdr, EC_COAP_HDR_SIZE);
    FWRITE_STR(f, "\n");
    FWRITE_PRINT(f, "  T: %s\n", wrap_null_str(buf, sizeof buf, "t",
                &ec_model_str, h->t));
    FWRITE_PRINT(f, "  OC: %u\n", h->oc);
    FWRITE_PRINT(f, "  Code: %s\n", wrap_null_str(buf, sizeof buf, "c",
                &ec_code_str, h->code));
    FWRITE_PRINT(f, "  MID: 0x%02x\n", h->mid);
    FWRITE_PRINT(f, "\n");

    FWRITE_STR(f, "[Options]:\n");

    TAILQ_FOREACH(o, &pdu->opts.bundle, next)
    {
        FWRITE_PRINT(f, "  %s: ", wrap_null_str(buf, sizeof buf, "o",
                    &ec_opt_sym2str, o->sym));

        switch (o->t) 
        {
            case EC_OPT_TYPE_STRING:
                FWRITE_PRINT(f, "%s", o->v);
                break;

            case EC_OPT_TYPE_OPAQUE:
            default:
                FWRITE_HEX(f, o->v, o->l);
                break;
        }

        FWRITE_PRINT(f, "\n");
    }
    FWRITE_PRINT(f, "\n");

    if (pdu->payload_sz)
    {
        FWRITE_STR(f, "[Payload]: ");
        FWRITE_HEX(f, pdu->payload, pdu->payload_sz);
        FWRITE_PRINT(f, "\n\n");
    }

    /* Fall through. */
err:
    if (f)
        fclose(f);
    return;

#undef FWRITE_STR
#undef FWRITE_PRINT
#undef FWRITE_HEX
#undef WRAP_UNDEF
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
        ec_opts_clear(&pdu->opts);
        u_free(pdu->payload);
        u_free(pdu);
    }
}

int ec_pdu_get_type(ec_pdu_t *pdu, uint8_t *t)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (t == NULL, -1);

    /* XXX Check that header has been decoded. */

    *t = pdu->hdr_bits.t;

    return 0;
}

int ec_pdu_get_mid(ec_pdu_t *pdu, uint16_t *mid)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (mid == NULL, -1);

    /* XXX Check that header has been decoded. */

    *mid = pdu->hdr_bits.mid;

    return 0;
}


