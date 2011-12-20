#include <u/libu.h>
#include "evcoap_prv.h"
#include "evcoap.h"

struct ec_s
{
    struct event_base *base;
    struct evdns_base *dns;
};

struct ec_pdu_s
{
    enum { EC_PDU_INVALID, EC_PDU_REQ, EC_PDU_RES } what;
#define PDU_IS_REQ(pdu) ((pdu) != NULL && (pdu)->what == EC_PDU_REQ)
#define PDU_IS_RES(pdu) ((pdu) != NULL && (pdu)->what == EC_PDU_RES)

    ec_method_t method;
    u_uri_t *uri;

    ev_uint8_t *payload;
    size_t payload_sz;

    ec_rc_t resp_code;

    ev_uint8_t has_proxy;
    char proxy_addr[512];

    struct ec_opts_s opts;

    ev_uint8_t is_mcast;
};

static ec_pdu_t *ec_request_new(ec_method_t m, const char *uri, 
        const char *proxy_host, ev_uint16_t proxy_port);
static void ec_request_free(struct ec_pdu_s *req);

static int ec_request_set_proxy(struct ec_pdu_s *req, const char *proxy_host,
        ev_uint16_t proxy_port);
static int ec_request_set_method(struct ec_pdu_s *req, ec_method_t m);
static int ec_request_set_uri(struct ec_pdu_s *req, const char *uri);


/**
 *  \brief  TODO
 */
ec_t *ec_init(struct event_base *base, struct evdns_base *dns)
{
    struct ec_s *coap = NULL;

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
void ec_term(ec_t *coap)
{
    if (coap == NULL)
        return;

    u_free(coap);

    return;
}

/**
 *  \brief  TODO
 */
ec_pdu_t *ec_new_request(ec_method_t m, const char *uri)
{
    return ec_request_new(m, uri, NULL, 0);
}

/**
 *  \brief  TODO
 */
ec_pdu_t *ec_new_proxy_request(ec_method_t m, const char *uri,
        const char *proxy_host, ev_uint16_t proxy_port)
{
    return ec_request_new(m, uri, proxy_host, proxy_port);
}

/**
 *  \brief  TODO
 */
int ec_send_request(ec_t *coap, ec_pdu_t *req, 
        ec_pdu_type_t pt, ec_client_cb_t cb, void *cb_args)
{
    return -1;
}

/**
 *  \brief  TODO
 */
int ec_bind_socket(ec_t *coap, const char *addr, ev_uint16_t port)
{
    return -1;
}

/**
 *  \brief  TODO
 */
int ec_set_cb(ec_t *coap, const char *patt, ec_server_cb_t cb,
        void *cb_args, ev_uint8_t observable)
{
    return -1;
}

/**
 *  \brief  TODO
 */
int ec_set_gencb(ec_t *coap, ec_server_cb_t cb, void *cb_args,
        ev_uint8_t observable)
{
    return -1;
}

/**
 *  \brief  TODO
 */
int ec_set_payload(ec_pdu_t *req, ev_uint8_t *payload, size_t sz)
{
    dbg_return_if (req == NULL || req->what != EC_PDU_REQ, -1);
    dbg_return_if (payload == NULL, -1);
    dbg_return_if (sz == 0, -1);

    dbg_return_sif ((req->payload = u_memdup(payload, sz)) == NULL, -1);

    req->payload_sz = sz;

    return 0;
}

/**
 *  \brief  TODO
 */
int ec_set_response_code(ec_pdu_t *res, ec_rc_t rc)
{
    dbg_return_if (res == NULL || res->what != EC_PDU_RES, -1);
    dbg_return_if (!EC_IS_RESP_CODE(rc), -1);

    res->resp_code = rc;

    return -1;
}

/**
 *  \brief  TODO
 */
int ec_add_content_type_option(struct ec_pdu_s *req, ev_uint16_t ct)
{
    /* Valid range is 0-65535.
     * EC_CT_* enum values are provided for registered content types.
     * 0-2 B length is enforced by 16-bit 'ct'. */

    dbg_return_if (!PDU_IS_REQ(req), -1);

    return ec_opt_add_uint(&req->opts, EC_OPT_CONTENT_TYPE, ct);
}

/**
 *  \brief  TODO
 */
int ec_add_max_age_option(struct ec_pdu_s *req, ev_uint32_t ma)
{
    /* 0-4 B lenght is enforced by 32-bit 'ma'. */

    dbg_return_if (!PDU_IS_REQ(req), -1);

    return ec_opt_add_uint(&req->opts, EC_OPT_MAX_AGE, ma);
}

/**
 *  \brief  TODO
 */
int ec_add_proxy_uri_option(struct ec_pdu_s *req, const char *pu)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);
    dbg_return_if (pu == NULL, -1);
    dbg_return_if (!strlen(pu) || strlen(pu) > 270, -1); /* 1-270 B */

    return ec_opt_add_string(&req->opts, EC_OPT_PROXY_URI, pu);
}

/**
 *  \brief  TODO
 */
int ec_pdu_add_etag(struct ec_pdu_s *req, const ev_uint8_t *et,
        size_t et_len)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);
    dbg_return_if (et == NULL, -1);
    dbg_return_if (!et_len || et_len > 8, -1);  /* 1-8 B */

    return ec_opt_add_opaque(&req->opts, EC_OPT_ETAG, et, et_len);
}

/**
 *  \brief  TODO
 */
int ec_add_uri_host_option(struct ec_pdu_s *req, const char  *uh)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);
    dbg_return_if (uh == NULL, -1);
    dbg_return_if (!strlen(uh) || strlen(uh) > 270, -1);  /* 1-270 B */

    return ec_opt_add_string(&req->opts, EC_OPT_URI_HOST, uh);
}

/**
 *  \brief  TODO
 */
int ec_add_location_path_option(struct ec_pdu_s *req, const char *lp)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);
    dbg_return_if (lp == NULL, -1);
    dbg_return_if (!strlen(lp) || strlen(lp) > 270, -1);  /* 1-270 B */

    return ec_opt_add_string(&req->opts, EC_OPT_LOCATION_PATH, lp);
}

/**
 *  \brief  TODO
 */
int ec_add_uri_port_option(struct ec_pdu_s *req, ev_uint16_t up)
{
    /* 0-2 B length is enforced by 16-bit 'up'. */
    dbg_return_if (!PDU_IS_REQ(req), -1);

    return ec_opt_add_uint(&req->opts, EC_OPT_URI_PORT, up);
}

/**
 *  \brief  TODO
 */
int ec_add_location_query_option(struct ec_pdu_s *req, const char *lq)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);
    dbg_return_if (lq == NULL, -1);
    dbg_return_if (!strlen(lq) || strlen(lq) > 270, -1);  /* 1-270 B */

    return ec_opt_add_string(&req->opts, EC_OPT_LOCATION_QUERY, lq);
}

/**
 *  \brief  TODO
 */
int ec_add_uri_path_option(struct ec_pdu_s *req, const char *up)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);
    dbg_return_if (up == NULL, -1);
    dbg_return_if (!strlen(up) || strlen(up) > 270, -1);  /* 1-270 B */

    return ec_opt_add_string(&req->opts, EC_OPT_URI_PATH, up);
}

/**
 *  \brief  TODO
 */
int ec_add_token_option(struct ec_pdu_s *req, const ev_uint8_t *t,
        size_t t_len)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);
    dbg_return_if (t == NULL, -1);
    dbg_return_if (!t_len || t_len > 8, -1);  /* 1-8 B */

    return ec_opt_add_opaque(&req->opts, EC_OPT_TOKEN, t, t_len);
}

/**
 *  \brief  TODO
 */
int ec_add_accept_option(struct ec_pdu_s *req, ev_uint16_t a)
{
    /* 0-2 B length is enforced by 16-bit 'a'. */
    dbg_return_if (!PDU_IS_REQ(req), -1);

    return ec_opt_add_uint(&req->opts, EC_OPT_ACCEPT, a);
}

/**
 *  \brief  TODO
 */
int ec_add_if_match_option(struct ec_pdu_s *req, const ev_uint8_t *im,
        size_t im_len)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);
    dbg_return_if (im == NULL, -1);
    dbg_return_if (!im_len || im_len > 8, -1);  /* 1-8 B */

    return ec_opt_add_opaque(&req->opts, EC_OPT_IF_MATCH, im, im_len);
}

/**
 *  \brief  TODO
 */
int ec_add_uri_query_option(struct ec_pdu_s *req, const char *uq)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);
    dbg_return_if (uq == NULL, -1);
    dbg_return_if (!strlen(uq) || strlen(uq) > 270, -1);  /* 1-270 B */

    return ec_opt_add_string(&req->opts, EC_OPT_URI_QUERY, uq);
}

/**
 *  \brief  TODO
 */
int ec_add_if_none_match_option(struct ec_pdu_s *req)
{
    dbg_return_if (!PDU_IS_REQ(req), -1);

    return ec_opt_add_empty(&req->opts, EC_OPT_IF_NONE_MATCH);
}

/**
 *  \brief  TODO
 */
int ec_add_observe_option(struct ec_pdu_s *req, ev_uint16_t o)
{
    /* 0-2 B length is enforced by 16-bit 'o'. */
    dbg_return_if (!PDU_IS_REQ(req), -1);

    return ec_opt_add_uint(&req->opts, EC_OPT_OBSERVE, o);
}

/**
 *  \brief  TODO
 */
int ec_add_max_ofe_option(struct ec_pdu_s *req, ev_uint32_t mo)
{
    /* 0-2 B length is enforced by 32-bit 'mo'. */
    dbg_return_if (!PDU_IS_REQ(req), -1);

    return ec_opt_add_uint(&req->opts, EC_OPT_MAX_OFE, mo);
}

/**
 *  \brief  TODO
 */
int ec_update_representation(const char *uri, const ev_uint8_t *rep,
        size_t rep_len, ec_mt_t media_type)
{
    return -1;
}

static int ec_request_set_method(struct ec_pdu_s *req, ec_method_t m)
{
    dbg_return_if (m < EC_GET || m > EC_DELETE, -1);

    req->method = m;

    return 0;
}

static int ec_request_set_proxy(struct ec_pdu_s *req, const char *proxy_host,
        ev_uint16_t proxy_port)
{
    dbg_return_if (proxy_host == NULL || *proxy_host == '\0', -1);

    if (proxy_port == 0)
        proxy_port = EC_DEFAULT_PORT;

    dbg_err_if (u_snprintf(req->proxy_addr, sizeof req->proxy_addr,
                "%s:%u", proxy_host, proxy_port));

    req->has_proxy = 1;

    return 0;
err:
    return -1;
}

static int ec_request_set_uri(struct ec_pdu_s *req, const char *uri)
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

static void ec_request_free(struct ec_pdu_s *req)
{
    if (req == NULL)
        return;

    dbg_return_if (req->what != EC_PDU_REQ, );

    u_free(req->payload);
    u_free(req);

    return;
}

static ec_pdu_t *ec_request_new(ec_method_t m, const char *uri, 
        const char *proxy_host, ev_uint16_t proxy_port)
{
    struct ec_pdu_s *req = NULL;

    dbg_err_sif ((req = u_zalloc(sizeof *req)) == NULL);

    req->what = EC_PDU_REQ;

    /* Must be done first because the following URI validation also
     * depends on the fact that this request is expected to go through
     * a proxy or not. */
    if (proxy_host)
        dbg_err_if (ec_request_set_proxy(req, proxy_host, proxy_port));

    dbg_err_if (ec_request_set_method(req, m));
    dbg_err_if (ec_request_set_uri(req, uri));

    return req;
err:
    if (req)
        ec_request_free(req);
    return NULL;
}


