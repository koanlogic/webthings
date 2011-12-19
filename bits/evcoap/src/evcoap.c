#include <u/libu.h>
#include "evcoap.h"

struct evcoap_s
{
    struct event_base *base;
    struct evdns_base *dns;
};

struct evcoap_pdu_s
{
    evcoap_method_t method;
    u_uri_t *uri;

    ev_uint8_t has_proxy;
    char proxy_addr[512];

    TAILQ_ENTRY(evcoap_pdu_s) next;
};

static int request_set_uri(struct evcoap_pdu_s *req, const char *uri);
static int request_set_method(struct evcoap_pdu_s *req, evcoap_method_t m);
static int request_set_proxy(struct evcoap_pdu_s *req, const char *proxy_host,
        ev_uint16_t proxy_port);
static void request_free(struct evcoap_pdu_s *req);
evcoap_pdu_t *request_new(evcoap_method_t m, const char *uri, 
        const char *proxy_host, ev_uint16_t proxy_port);

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
    return -1;
}

/**
 *  \brief  TODO
 */
int evcoap_set_response_code(evcoap_pdu_t *res, evcoap_rc_t rc)
{
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

    u_free(req);

    return;
}

evcoap_pdu_t *request_new(evcoap_method_t m, const char *uri, 
        const char *proxy_host, ev_uint16_t proxy_port)
{
    struct evcoap_pdu_s *req = NULL;

    dbg_err_sif ((req = u_zalloc(sizeof *req)) == NULL);

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

