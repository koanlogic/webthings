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
    ev_uint8_t *enc;                    /* Encoded options. */
    size_t enc_sz;

    TAILQ_HEAD(, evcoap_opt_s) opts;    /* Decoded options. */
};

struct evcoap_pdu_s
{
    enum { EVCOAP_PDU_INVALID, EVCOAP_PDU_REQ, EVCOAP_PDU_RES } what;

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

static struct evcoap_opt_s *opt_new(evcoap_opt_t sym, size_t l, ev_uint8_t *v);
static void opt_free(struct evcoap_opt_s *opt);
static evcoap_opt_type_t opt_sym2type(evcoap_opt_t sym);

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
int evcoap_add_ifmatch_option(evcoap_pdu_t *req, ev_uint8_t *tag, size_t sz)
{
    return -1;
}

/**
 *  \brief  TODO
 */
int evcoap_add_accept_option(evcoap_pdu_t *req, evcoap_mt_t mt)
{
    return -1;
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

static struct evcoap_opt_s *opt_new(evcoap_opt_t sym, size_t l, ev_uint8_t *v)
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

