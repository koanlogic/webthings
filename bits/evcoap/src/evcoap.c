#include <u/libu.h>
#include "evcoap.h"

#define EVCOAP_OPT_LEN_MAX  270

struct evcoap_s
{
    struct event_base *base;
    struct evdns_base *dns;
};

/* When introducing a new option, add a new symbol here and a corresponding
 * entry into the g_opts array. */
typedef enum
{
    EVCOAP_OPT_NONE = 0,
    
    EVCOAP_OPT_CONTENT_TYPE,
    EVCOAP_OPT_MAX_AGE,
    EVCOAP_OPT_PROXY_URI,
    EVCOAP_OPT_ETAG,
    EVCOAP_OPT_URI_HOST,
    EVCOAP_OPT_LOCATION_PATH,
    EVCOAP_OPT_URI_PORT,
    EVCOAP_OPT_LOCATION_QUERY,
    EVCOAP_OPT_URI_PATH,
    EVCOAP_OPT_OBSERVE,
    EVCOAP_OPT_TOKEN,
    EVCOAP_OPT_ACCEPT,
    EVCOAP_OPT_IF_MATCH,
    EVCOAP_OPT_MAX_OFE,
    EVCOAP_OPT_URI_QUERY,
    EVCOAP_OPT_IF_NONE_MATCH,
    
    EVCOAP_OPT_MAX = EVCOAP_OPT_IF_NONE_MATCH + 1
} evcoap_opt_t;
#define EVCOAP_OPT_SYM_VALID(sy) (sy > EVCOAP_OPT_NONE && sy < EVCOAP_OPT_MAX)

typedef enum
{
    EVCOAP_OPT_TYPE_INVALID,
    EVCOAP_OPT_TYPE_UINT,
    EVCOAP_OPT_TYPE_STRING,
    EVCOAP_OPT_TYPE_OPAQUE,
    EVCOAP_OPT_TYPE_EMPTY   /* No type (e.g. if-none-match) */
} evcoap_opt_type_t;

struct opt_rec {
    size_t n;               /* Option number. */
    const char *s;          /* Option human readable name. */
    evcoap_opt_type_t t;
} g_opts[] = {
    { 0,  "Invalid",        EVCOAP_OPT_TYPE_INVALID },
    { 1,  "Content-Type",   EVCOAP_OPT_TYPE_UINT },
    { 2,  "Max-Age",        EVCOAP_OPT_TYPE_UINT },
    { 3,  "Proxy-URI",      EVCOAP_OPT_TYPE_STRING },
    { 4,  "ETag",           EVCOAP_OPT_TYPE_OPAQUE },
    { 5,  "URI-Host",       EVCOAP_OPT_TYPE_STRING },
    { 6,  "Location-Path",  EVCOAP_OPT_TYPE_STRING },
    { 7,  "URI-Port",       EVCOAP_OPT_TYPE_UINT },
    { 8,  "Location-Query", EVCOAP_OPT_TYPE_STRING },
    { 9,  "URI-Path",       EVCOAP_OPT_TYPE_STRING },
    { 10, "Observe",        EVCOAP_OPT_TYPE_UINT },
    { 11, "Token",          EVCOAP_OPT_TYPE_OPAQUE },
    { 12, "Accept",         EVCOAP_OPT_TYPE_UINT },
    { 13, "If-Match",       EVCOAP_OPT_TYPE_OPAQUE },
    { 14, "Max-OFE",        EVCOAP_OPT_TYPE_UINT },
    { 15, "URI-Query",      EVCOAP_OPT_TYPE_STRING },
    { 21, "If-None-Match",  EVCOAP_OPT_TYPE_EMPTY }
};
#define EVCOAP_OPTS_MAX (sizeof g_opts / sizeof(struct opt_rec))

/* Maximum number of options that can be encoded in a single CoAP PDU. */
#define EVCOAP_PROTO_MAX_OPTIONS    15

struct evcoap_opt_s
{
    evcoap_opt_t sym;
    evcoap_opt_type_t t;
    size_t l;
    ev_uint8_t *v;

    TAILQ_ENTRY(evcoap_opt_s) next;
};

struct evcoap_opts_s
{
    ev_uint8_t *enc;
    size_t enc_sz;

    size_t noptions;
    TAILQ_HEAD(evcoap_opts, evcoap_opt_s) bundle;
};

struct evcoap_pdu_s
{
    enum { EVCOAP_PDU_INVALID, EVCOAP_PDU_REQ, EVCOAP_PDU_RES } what;
#define PDU_IS_REQ(pdu) ((pdu) != NULL && (pdu)->what == EVCOAP_PDU_REQ)
#define PDU_IS_RES(pdu) ((pdu) != NULL && (pdu)->what == EVCOAP_PDU_RES)

    evcoap_method_t method;
    u_uri_t *uri;

    ev_uint8_t *payload;
    size_t payload_sz;

    evcoap_rc_t resp_code;

    ev_uint8_t has_proxy;
    char proxy_addr[512];

    struct evcoap_opts_s opts;

    ev_uint8_t is_mcast;
};


evcoap_pdu_t *request_new(evcoap_method_t m, const char *uri, 
        const char *proxy_host, ev_uint16_t proxy_port);
static void request_free(struct evcoap_pdu_s *req);
static int request_set_uri(struct evcoap_pdu_s *req, const char *uri);
static int request_set_method(struct evcoap_pdu_s *req, evcoap_method_t m);
static int request_set_proxy(struct evcoap_pdu_s *req, const char *proxy_host,
        ev_uint16_t proxy_port);

static struct evcoap_opt_s *opt_new(evcoap_opt_t sym, size_t l,
        const ev_uint8_t *v);
static void opt_free(struct evcoap_opt_s *opt);
static evcoap_opt_type_t opt_sym2type(evcoap_opt_t sym);
static int opt_push(struct evcoap_opts_s *opts, struct evcoap_opt_s *o);
static int opt_add(struct evcoap_opts_s *opts, evcoap_opt_t sym,
        const ev_uint8_t *v, size_t l);
static int opt_add_raw(struct evcoap_opts_s *opts, evcoap_opt_t sym,
        const ev_uint8_t *v,  size_t l);
static int opt_encode_uint(ev_uint64_t ui, ev_uint8_t *e, size_t *elen);
static int opt_add_empty(struct evcoap_opts_s *opts, evcoap_opt_t sym);
static int opt_add_opaque(struct evcoap_opts_s *opts, evcoap_opt_t sym,
        const ev_uint8_t *v,  size_t l);
static int opt_add_string(struct evcoap_opts_s *opts, evcoap_opt_t sym,
        const char *s);
static int opt_add_uint(struct evcoap_opts_s *opts, evcoap_opt_t sym,
        ev_uint64_t v);



/**
 *  \brief  TODO
 */
evcoap_t *evcoap_init(struct event_base *base, struct evdns_base *dns)
{
    struct evcoap_s *coap = NULL;

    dbg_return_if (base == NULL, NULL);
    dbg_return_if (dns == NULL, NULL);
    
    dbg_err_sif ((coap = u_zalloc(sizeof *coap)) == NULL);

    coap->base = base;
    coap->dns = dns;

    return coap;
err:
    return NULL;
}

/**
 *  \brief  TODO
 */
void evcoap_term(evcoap_t *coap)
{
    if (coap == NULL)
        return;

    u_free(coap);

    return;
}

/**
 *  \brief  TODO
 */
evcoap_pdu_t *evcoap_new_request(evcoap_method_t m, const char *uri)
{
    return request_new(m, uri, NULL, 0);
}

/**
 *  \brief  TODO
 */
evcoap_pdu_t *evcoap_new_proxy_request(evcoap_method_t m, const char *uri,
        const char *proxy_host, ev_uint16_t proxy_port)
{
    return request_new(m, uri, proxy_host, proxy_port);
}

/**
 *  \brief  TODO
 */
int evcoap_send_request(evcoap_t *coap, evcoap_pdu_t *req, 
        evcoap_pdu_type_t pt, evcoap_client_cb_t cb, void *cb_args)
{
    return -1;
}

/**
 *  \brief  TODO
 */
int evcoap_bind_socket(evcoap_t *coap, const char *addr, ev_uint16_t port)
{
    return -1;
}

/**
 *  \brief  TODO
 */
int evcoap_set_cb(evcoap_t *coap, const char *patt, evcoap_server_cb_t cb,
        void *cb_args, ev_uint8_t observable)
{
    return -1;
}

/**
 *  \brief  TODO
 */
int evcoap_set_gencb(evcoap_t *coap, evcoap_server_cb_t cb, void *cb_args,
        ev_uint8_t observable)
{
    return -1;
}

/**
 *  \brief  TODO
 */
int evcoap_set_payload(evcoap_pdu_t *req, ev_uint8_t *payload, size_t sz)
{
    dbg_return_if (req == NULL || req->what != EVCOAP_PDU_REQ, -1);
    dbg_return_if (payload == NULL, -1);
    dbg_return_if (sz == 0, -1);

    dbg_return_sif ((req->payload = u_memdup(payload, sz)) == NULL, -1);

    req->payload_sz = sz;

    return 0;
}

/**
 *  \brief  TODO
 */
int evcoap_set_response_code(evcoap_pdu_t *res, evcoap_rc_t rc)
{
    dbg_return_if (res == NULL || res->what != EVCOAP_PDU_RES, -1);
    dbg_return_if (!EVCOAP_IS_RESP_CODE(rc), -1);

    res->resp_code = rc;

    return -1;
}

/**
 *  \brief  TODO
 */
int evcoap_add_content_type_option(struct evcoap_pdu_s *req, ev_uint16_t ct)
{
    /* Valid range is 0-65535.
     * EVCOAP_CT_* enum values are provided for registered content types.
     * 0-2 B length is enforced by 16-bit 'ct'. */

    dbg_return_if (!PDU_IS_REQ(req), -1);

    return opt_add_uint(&req->opts, EVCOAP_OPT_CONTENT_TYPE, ct);
}

/**
 *  \brief  TODO
 */
int evcoap_add_max_age_option(struct evcoap_pdu_s *req, ev_uint32_t ma)
{
    /* 0-4 B lenght is enforced by 32-bit 'ma'. */

    dbg_return_if (!PDU_IS_REQ(req), -1);

    return opt_add_uint(&req->opts, EVCOAP_OPT_MAX_AGE, ma);
}

/**
 *  \brief  TODO
 */
int evcoap_add_proxy_uri_option(struct evcoap_pdu_s *req, const char *pu)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);
    dbg_return_if (pu == NULL, -1);
    dbg_return_if (!strlen(pu) || strlen(pu) > 270, -1); /* 1-270 B */

    return opt_add_string(&req->opts, EVCOAP_OPT_PROXY_URI, pu);
}

/**
 *  \brief  TODO
 */
int evcoap_pdu_add_etag(struct evcoap_pdu_s *req, const ev_uint8_t *et,
        size_t et_len)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);
    dbg_return_if (et == NULL, -1);
    dbg_return_if (!et_len || et_len > 8, -1);  /* 1-8 B */

    return opt_add_opaque(&req->opts, EVCOAP_OPT_ETAG, et, et_len);
}

/**
 *  \brief  TODO
 */
int evcoap_add_uri_host_option(struct evcoap_pdu_s *req, const char  *uh)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);
    dbg_return_if (uh == NULL, -1);
    dbg_return_if (!strlen(uh) || strlen(uh) > 270, -1);  /* 1-270 B */

    return opt_add_string(&req->opts, EVCOAP_OPT_URI_HOST, uh);
}

/**
 *  \brief  TODO
 */
int evcoap_add_location_path_option(struct evcoap_pdu_s *req, const char *lp)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);
    dbg_return_if (lp == NULL, -1);
    dbg_return_if (!strlen(lp) || strlen(lp) > 270, -1);  /* 1-270 B */

    return opt_add_string(&req->opts, EVCOAP_OPT_LOCATION_PATH, lp);
}

/**
 *  \brief  TODO
 */
int evcoap_add_uri_port_option(struct evcoap_pdu_s *req, ev_uint16_t up)
{
    /* 0-2 B length is enforced by 16-bit 'up'. */
    dbg_return_if (!PDU_IS_REQ(req), -1);

    return opt_add_uint(&req->opts, EVCOAP_OPT_URI_PORT, up);
}

/**
 *  \brief  TODO
 */
int evcoap_add_location_query_option(struct evcoap_pdu_s *req, const char *lq)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);
    dbg_return_if (lq == NULL, -1);
    dbg_return_if (!strlen(lq) || strlen(lq) > 270, -1);  /* 1-270 B */

    return opt_add_string(&req->opts, EVCOAP_OPT_LOCATION_QUERY, lq);
}

/**
 *  \brief  TODO
 */
int evcoap_add_uri_path_option(struct evcoap_pdu_s *req, const char *up)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);
    dbg_return_if (up == NULL, -1);
    dbg_return_if (!strlen(up) || strlen(up) > 270, -1);  /* 1-270 B */

    return opt_add_string(&req->opts, EVCOAP_OPT_URI_PATH, up);
}

/**
 *  \brief  TODO
 */
int evcoap_add_token_option(struct evcoap_pdu_s *req, const ev_uint8_t *t,
        size_t t_len)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);
    dbg_return_if (t == NULL, -1);
    dbg_return_if (!t_len || t_len > 8, -1);  /* 1-8 B */

    return opt_add_opaque(&req->opts, EVCOAP_OPT_TOKEN, t, t_len);
}

/**
 *  \brief  TODO
 */
int evcoap_add_accept_option(struct evcoap_pdu_s *req, ev_uint16_t a)
{
    /* 0-2 B length is enforced by 16-bit 'a'. */
    dbg_return_if (!PDU_IS_REQ(req), -1);

    return opt_add_uint(&req->opts, EVCOAP_OPT_ACCEPT, a);
}

/**
 *  \brief  TODO
 */
int evcoap_add_if_match_option(struct evcoap_pdu_s *req, const ev_uint8_t *im,
        size_t im_len)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);
    dbg_return_if (im == NULL, -1);
    dbg_return_if (!im_len || im_len > 8, -1);  /* 1-8 B */

    return opt_add_opaque(&req->opts, EVCOAP_OPT_IF_MATCH, im, im_len);
}

/**
 *  \brief  TODO
 */
int evcoap_add_uri_query_option(struct evcoap_pdu_s *req, const char *uq)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);
    dbg_return_if (uq == NULL, -1);
    dbg_return_if (!strlen(uq) || strlen(uq) > 270, -1);  /* 1-270 B */

    return opt_add_string(&req->opts, EVCOAP_OPT_URI_QUERY, uq);
}

/**
 *  \brief  TODO
 */
int evcoap_add_if_none_match_option(struct evcoap_pdu_s *req)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);

    return opt_add_empty(&req->opts, EVCOAP_OPT_IF_NONE_MATCH);
}

/**
 *  \brief  TODO
 */
int evcoap_add_observe_option(struct evcoap_pdu_s *req, ev_uint16_t o)
{
    /* 0-2 B length is enforced by 16-bit 'o'. */
    dbg_return_if (!PDU_IS_REQ(req), -1);

    return opt_add_uint(&req->opts, EVCOAP_OPT_OBSERVE, o);
}

/**
 *  \brief  TODO
 */
int evcoap_add_max_ofe_option(struct evcoap_pdu_s *req, ev_uint32_t mo)
{
    /* 0-2 B length is enforced by 32-bit 'mo'. */
    dbg_return_if (!PDU_IS_REQ(req), -1);

    return opt_add_uint(&req->opts, EVCOAP_OPT_MAX_OFE, mo);
}

/**
 *  \brief  TODO
 */
int evcoap_update_representation(const char *uri, const ev_uint8_t *rep,
        size_t rep_len, evcoap_mt_t media_type)
{
    return -1;
}

static int request_set_method(struct evcoap_pdu_s *req, evcoap_method_t m)
{
    dbg_return_if (m < EVCOAP_GET || m > EVCOAP_DELETE, -1);

    req->method = m;

    return 0;
}

static int request_set_proxy(struct evcoap_pdu_s *req, const char *proxy_host,
        ev_uint16_t proxy_port)
{
    dbg_return_if (proxy_host == NULL || *proxy_host == '\0', -1);

    if (proxy_port == 0)
        proxy_port = EVCOAP_DEFAULT_PORT;

    dbg_err_if (u_snprintf(req->proxy_addr, sizeof req->proxy_addr,
                "%s:%u", proxy_host, proxy_port));

    req->has_proxy = 1;

    return 0;
err:
    return -1;
}

static int request_set_uri(struct evcoap_pdu_s *req, const char *uri)
{
    u_uri_t *u = NULL;
    const char *scheme, *auth;

    /* Parse URI. */
    dbg_err_if (u_uri_crumble(uri, 0, &u));

    /* Do minimal URI validation: expect scheme + authority at least. */
    dbg_err_if ((scheme = u_uri_get_scheme(u)) == NULL || *scheme == '\0');
    dbg_err_if ((auth = u_uri_get_authority(u)) == NULL || *auth == '\0');

    /* Expect scheme==coap for any non proxy request. */
    dbg_err_ifm (!req->has_proxy && strcasecmp(scheme, "coap"),
            "expect URI with coap scheme when doing non-proxy requests");

    return 0;
err:
    return -1;
}

static void request_free(struct evcoap_pdu_s *req)
{
    if (req == NULL)
        return;

    dbg_return_if (req->what != EVCOAP_PDU_REQ, );

    u_free(req->payload);
    u_free(req);

    return;
}

evcoap_pdu_t *request_new(evcoap_method_t m, const char *uri, 
        const char *proxy_host, ev_uint16_t proxy_port)
{
    struct evcoap_pdu_s *req = NULL;

    dbg_err_sif ((req = u_zalloc(sizeof *req)) == NULL);

    req->what = EVCOAP_PDU_REQ;

    /* Must be done first because the following URI validation also
     * depends on the fact that this request is expected to go through
     * a proxy or not. */
    if (proxy_host)
        dbg_err_if (request_set_proxy(req, proxy_host, proxy_port));

    dbg_err_if (request_set_method(req, m));
    dbg_err_if (request_set_uri(req, uri));

    return req;
err:
    if (req)
        request_free(req);
    return NULL;
}

static struct evcoap_opt_s *opt_new(evcoap_opt_t sym, size_t l, 
        const ev_uint8_t *v)
{
    size_t vlen;
    struct evcoap_opt_s *opt = NULL;

    dbg_err_sif ((opt = u_zalloc(sizeof *opt)) == NULL);

    opt->sym = sym;

    switch ((opt->t = opt_sym2type(sym)))
    {
        case EVCOAP_OPT_TYPE_INVALID:
            dbg_err("invalid option type");
        case EVCOAP_OPT_TYPE_EMPTY:
            return 0;
        default:
            break;
    }

    dbg_err_if ((opt->l = l) > EVCOAP_OPT_LEN_MAX);

    /* Make room for the option value. */
    vlen = (opt->t != EVCOAP_OPT_TYPE_STRING) ? opt->l : opt->l + 1;
    dbg_err_sif ((opt->v = u_malloc(vlen)) == NULL);
    memcpy(opt->v, v, opt->l);

    /* Be C friendly: NUL-terminate in case it's a string. */
    if (opt->t == EVCOAP_OPT_TYPE_STRING)
        opt->v[vlen - 1] = '\0';

    return opt;
err:
    if (opt)
        opt_free(opt);
    return NULL;
}

static void opt_free(struct evcoap_opt_s *opt)
{
    if (opt)
    {
        u_free(opt->v);
        u_free(opt);
    }
}

static evcoap_opt_type_t opt_sym2type(evcoap_opt_t sym)
{
    dbg_return_if (!EVCOAP_OPT_SYM_VALID(sym), EVCOAP_OPT_TYPE_INVALID);

    return g_opts[sym].t;
}   

static int opt_push(struct evcoap_opts_s *opts, struct evcoap_opt_s *o)
{
    struct evcoap_opt_s *tmp;
    
    dbg_return_if (opts->noptions == EVCOAP_PROTO_MAX_OPTIONS, -1);
    
    /* 
     * Ordered (lo[0]..hi[n]) insertion of new elements.
     */
    
    /* Empty. */
    if (TAILQ_EMPTY(&opts->bundle))
    {
        TAILQ_INSERT_TAIL(&opts->bundle, o, next);
        goto end;
    }
    
    /* Not the lowest. */
    TAILQ_FOREACH_REVERSE(tmp, &opts->bundle, evcoap_opts, next)
    {
        if (o->sym >= tmp->sym)
        {
            TAILQ_INSERT_AFTER(&opts->bundle, tmp, o, next);
            goto end;
        }
    }
    
    /* Lowest. */
    TAILQ_INSERT_HEAD(&opts->bundle, o, next);

    /* Fall through. */
end:
    opts->noptions += 1;
    return 0;
}

static int opt_add(struct evcoap_opts_s *opts, evcoap_opt_t sym,
        const ev_uint8_t *v, size_t l)
{
    struct evcoap_opt_s *o = NULL;

    dbg_err_if ((o = opt_new(sym, l, v)) == NULL);
    dbg_err_if (opt_push(opts, o));
    o = NULL;

    return 0;
err:
    if (o)
        opt_free(o);
    return -1;
}

/* 'v' is the complete value, which will be fragmented in one or more option 
 *  * slots if needed. */
static int opt_add_raw(struct evcoap_opts_s *opts, evcoap_opt_t sym,
        const ev_uint8_t *v,  size_t l)
{
    size_t nseg, offset = 0,
           full_seg_no = l / EVCOAP_OPT_LEN_MAX,
           rem = l % EVCOAP_OPT_LEN_MAX,
           to_be_used_opts = (full_seg_no + ((rem || !l) ? 1 : 0));
    
    /* First off, check if we have enough slots available
     * to encode the supplied option. */
    dbg_err_ifm (opts->noptions + to_be_used_opts > EVCOAP_PROTO_MAX_OPTIONS,
            "not enough slots available to encode option");
    
    /* Handle option fragmentation. */
    for (nseg = 0; nseg < full_seg_no; nseg++)
    {
        dbg_err_if (opt_add(opts, sym, v + offset, EVCOAP_OPT_LEN_MAX));
    
        /* Shift offset to point next fragment. */
        offset = nseg * EVCOAP_OPT_LEN_MAX;
    }
    
    /* Take care of the "remainder" slot (or an empty option.)
     * (TODO check that option is allowed to be zero length?) */
    if (rem || !l)
    {
        dbg_err_if (opt_add(opts, sym, v + offset, !l ? 0 : rem));
    }
    
    return 0;
err:
    return -1;
}

static int opt_add_uint(struct evcoap_opts_s *opts, evcoap_opt_t sym, 
        ev_uint64_t v)
{
    ev_uint8_t e[8];
    size_t elen = sizeof e;

    dbg_return_if (opt_sym2type(sym) != EVCOAP_OPT_TYPE_UINT, -1);
    dbg_return_if (opt_encode_uint(v, e, &elen), -1);

    return opt_add_raw(opts, sym, e, elen);
}

static int opt_add_string(struct evcoap_opts_s *opts, evcoap_opt_t sym,
        const char *s)
{
    dbg_return_if (opt_sym2type(sym) != EVCOAP_OPT_TYPE_STRING, -1);

    return opt_add_raw(opts, sym, (ev_uint8_t *) s, strlen(s));
}

static int opt_add_opaque(struct evcoap_opts_s *opts, evcoap_opt_t sym,
        const ev_uint8_t *v,  size_t l)
{
    dbg_return_if (opt_sym2type(sym) != EVCOAP_OPT_TYPE_OPAQUE, -1);

    return opt_add_raw(opts, sym, v, l);
}

static int opt_add_empty(struct evcoap_opts_s *opts, evcoap_opt_t sym)
{
    dbg_return_if (opt_sym2type(sym) != EVCOAP_OPT_TYPE_EMPTY, -1);

    return opt_add_raw(opts, sym, NULL, 0);
}

/* 'elen' is value-result argument.  It MUST be initially set to the size
 * of 'e'.  On a successful return it will hold the lenght of the encoded 
 * uint (i.e. # of valid bytes in 'e'.) */
static int opt_encode_uint(ev_uint64_t ui, ev_uint8_t *e, size_t *elen)
{
    size_t i, j;
    
    ev_uint64_t ui_bytes[] =
    {
        (1ULL <<  8) - 1,
        (1ULL << 16) - 1,
        (1ULL << 24) - 1,
        (1ULL << 32) - 1,
        (1ULL << 40) - 1,
        (1ULL << 48) - 1,
        (1ULL << 56) - 1,
        UINT64_MAX
    };
    
    /* Pick size. */
    for (i = 0; i < (sizeof ui_bytes / sizeof(ev_uint64_t)); i++)
        if (ui_bytes[i] > ui)
            break;
    
    dbg_err_ifm (*elen < i + 1, "not enough bytes for encoding %llu", ui);
    
    /* XXX Assume LE host. */
    /* TODO BE host (nop). */
    for (j = 0; j <= i; ++j)
        e[j] = (ui >> (8 * j)) & 0xff;
    
    *elen = i + 1;
    
    return 0;
err:
    return -1;
}



