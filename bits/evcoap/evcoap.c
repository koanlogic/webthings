#include "evcoap.h"
#include "evcoap-internal.h"

struct evcoap *evcoap_new(struct event_base *base, struct evdns_base *dns)
{
    struct evcoap *coap = NULL;
    struct timeval pap = { .tv_sec = EVCOAP_ACK_CHORES_PERIOD, .tv_usec = 0 };
    struct timeval rqp = { .tv_sec = EVCOAP_RCVD_CHORES_PERIOD, .tv_usec = 0 };

    dbg_return_if (base == NULL, NULL);
    dbg_return_if (dns == NULL, NULL);

    dbg_err_sif ((coap = u_malloc(sizeof(struct evcoap))) == NULL);

    /* Tracing must be enabled explicitly. */
    coap->trace = 0;

    /* Callbacks. */
    TAILQ_INIT(&coap->callbacks);
    coap->fb = NULL;
    coap->fb_args = NULL;

    /* Bound sockets. */
    TAILQ_INIT(&coap->sockets);

    /* Duplicate detection machinery. */
    TAILQ_INIT(&coap->rcvd_queue);
    coap->rcvd_queue_handler_interval = NULL;

    /* Pending ACKs handler machinery. */
    TAILQ_INIT(&coap->pending_acks);
    coap->pending_acks_handler_interval = NULL;

    /*
     * Setup the CoAP machinery:
     *  - duplicated PDU handling;
     *  - automatic ACK handling
     */
    dbg_err_if ((coap->rcvd_queue_handler_interval = event_new(base, -1,
                    EV_PERSIST, evcoap_rcvd_queue_chores, coap)) == NULL);
    dbg_err_if (evtimer_add(coap->rcvd_queue_handler_interval, &rqp));

    dbg_err_if ((coap->pending_acks_handler_interval = event_new(base, -1,
                    EV_PERSIST, evcoap_pending_acks_chores, coap)) == NULL);
    dbg_err_if (evtimer_add(coap->pending_acks_handler_interval, &pap));

    /* Attach references to the event base and DNS base. */
    coap->dns = dns;
    coap->base = base;

    return coap;
err:
    u_free(coap);
    return NULL;
}

void evcoap_free(struct evcoap *coap)
{
    u_free(coap);

    /* TODO clean up the callback's list. */
    /* TODO clean up the socket's list. */
    /* TODO a million of other things... */

    return;
}

/* The payload data is copied into the PDU structure. */
int evcoap_pdu_set_payload(struct evcoap_pdu *pdu, const ev_uint8_t *p,
        size_t plen)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (plen > COAP_REQUEST_SIZE_MAX - EVCOAP_PDU_HDR_LEN, -1);

    /* Empty payload. */
    if (p == NULL)
    {
        pdu->payload = NULL;
        return 0;
    }

    dbg_return_if ((pdu->payload = u_memdup(p, plen)) == NULL, -1);

    return 0;
}

/* addr = "'['ipv6']'" | "ipv4" (literals) */
/* port == EV_UINT16_MAX => use default CoAP port */
int evcoap_bind_socket(struct evcoap *coap, const char *addr, ev_uint16_t port,
        ev_uint8_t secure)
{
    evutil_socket_t sd = (evutil_socket_t) -1;
    char addrport[1024] = { '\0' };
    struct evcoap_bound_socket *bs = NULL;
    struct sockaddr_storage ss;
    int ss_len = sizeof ss;

    dbg_return_if (coap == NULL, -1);
    dbg_return_if (addr == NULL, -1);

    /* 
     * Create the listening socket and mark it non-blocking.
     */
    dbg_err_if (u_snprintf(addrport, sizeof addrport, "%s:%u",
            addr, (port == EV_UINT16_MAX) ? COAP_DEFAULT_SERVER_PORT : port));

    dbg_err_ifm (evutil_parse_sockaddr_port(addrport,
                (struct sockaddr *) &ss, &ss_len),
            "Error parsing %s", addrport);

    dbg_err_ifm ((sd = evcoap_do_bind_socket(&ss, ss_len)) == -1,
            "Error binding %s", addrport);

    EVCOAP_TRACE("bound address: %s", addrport);

    dbg_err_sif (evutil_make_socket_nonblocking(sd));

    /* Attach a new bound socket to the supplied coap context. */
    dbg_err_if ((bs = evcoap_bound_socket_new(coap, sd, secure)) == NULL);
    TAILQ_INSERT_TAIL(&coap->sockets, bs, next);
    bs = NULL;

    return 0;
err:
    if (bs)
        evcoap_bound_socket_free(bs);
    if (sd != (evutil_socket_t) -1)
        evutil_closesocket(sd);
    return -1;
}

/* Set the fallback input processing function. */
int evcoap_set_gencb(struct evcoap *coap, 
        void (*cb)(struct evcoap_pdu *, const char *, void *), void *cb_args)
{
    dbg_return_if (coap == NULL, -1);
    /* 'cb' may be NULL. */

    coap->fb = cb;
    coap->fb_args = cb_args;

    return 0;
}

/* Remove fallback input processing function.
 * Equivalent to evcoap_set_gencb(coap, NULL, NULL). */
int evcoap_del_gencb(struct evcoap *coap)
{
    dbg_return_if (coap == NULL, -1);

    coap->fb = NULL;
    coap->fb_args = NULL;

    return 0;
}

/* Set callback function for a given URL. */
int evcoap_set_cb(struct evcoap *coap, const char *pattern,
        evcoap_cb_status_t (*cb)(struct evcoap_pdu *, const char *, void *),
        void *cb_args)
{
    return evcoap_set_cb_ex(coap, pattern, cb, cb_args, NULL);
}

int evcoap_set_cb_ex(struct evcoap *coap, const char *pattern,
        evcoap_cb_status_t (*cb)(struct evcoap_pdu *, const char *, void *),
        void *cb_args, const struct timeval *ack_timeout)
{
    struct evcoap_cb *tmp, *coap_cb = NULL;

    dbg_return_if (coap == NULL, -1);
    dbg_return_if (pattern == NULL, -1);

    /* Check if we have already installed a callback for this URL pattern. */
    TAILQ_FOREACH(tmp, &coap->callbacks, next) 
    {
        dbg_err_ifm (!strcmp(tmp->path, pattern), 
                "%s already registered", pattern);
    }

    /* Create a new callback structure to host the supplied URI pattern. */
    dbg_err_sif ((coap_cb = u_malloc(sizeof *coap_cb)) == NULL);

    /* Attach pattern to be served and related callback. */
    coap_cb->path = u_strdup(pattern);
    dbg_err_sif (coap_cb->path == NULL);
    coap_cb->fn = cb;
    coap_cb->fn_args = cb_args;

    /* 
     * Attach ACK timeout indication, if set.
     */
    if (ack_timeout)
    {
        coap_cb->ack_timeout = u_malloc(sizeof(struct timeval));
        dbg_err_sif (coap_cb->ack_timeout == NULL);

        *coap_cb->ack_timeout = *ack_timeout;
    }
    else
        coap_cb->ack_timeout = NULL;

    /* Push the new entry to the callback's list. */
    TAILQ_INSERT_TAIL(&coap->callbacks, coap_cb, next);
    coap_cb = NULL;

    return 0;
err:
    evcoap_cb_free(coap_cb);
    return -1;
}

int evcoap_del_cb(struct evcoap *coap, const char *path)
{
    struct evcoap_cb *tmp = NULL;

    TAILQ_FOREACH(tmp, &coap->callbacks, next)
    {
        if (!strcmp(tmp->path, path))
            break;
    }

    dbg_return_ifm (tmp == NULL, -1, "%s not registered", path);

    TAILQ_REMOVE(&coap->callbacks, tmp, next);
    evcoap_cb_free(tmp);

    return 0;
}

/* Valid range is 0-65535.  EVCOAP_CT_* enum values are provided for 
 * registered content types. */
int evcoap_pdu_add_content_type(struct evcoap_pdu *pdu, ev_uint16_t ct)
{
    dbg_return_if (pdu == NULL, -1);
    /* 0-2 B length is enforced by 16-bit 'ct'. */

    return evcoap_opt_add_uint(pdu, EVCOAP_OPT_CONTENT_TYPE, ct);
}

int evcoap_pdu_add_max_age(struct evcoap_pdu *pdu, ev_uint32_t ma)
{
    dbg_return_if (pdu == NULL, -1);
    /* 0-4 B lenght is enforced by 32-bit 'ma'. */

    return evcoap_opt_add_uint(pdu, EVCOAP_OPT_MAX_AGE, ma);
}

int evcoap_pdu_add_proxy_uri(struct evcoap_pdu *pdu, const char *pu)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (pu == NULL, -1);
    dbg_return_if (!strlen(pu) || strlen(pu) > 270, -1); /* 1-270 B */

    return evcoap_opt_add_string(pdu, EVCOAP_OPT_PROXY_URI, pu);
}

int evcoap_pdu_add_etag(struct evcoap_pdu *pdu, const ev_uint8_t *et,
        size_t et_len)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (et == NULL, -1);
    dbg_return_if (!et_len || et_len > 8, -1);  /* 1-8 B */

    return evcoap_opt_add_opaque(pdu, EVCOAP_OPT_ETAG, et, et_len);
}

int evcoap_pdu_add_uri_host(struct evcoap_pdu *pdu, const char  *uh)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (uh == NULL, -1);
    dbg_return_if (!strlen(uh) || strlen(uh) > 270, -1);  /* 1-270 B */

    return evcoap_opt_add_string(pdu, EVCOAP_OPT_URI_HOST, uh);
}

int evcoap_pdu_add_location_path(struct evcoap_pdu *pdu, const char *lp)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (lp == NULL, -1);
    dbg_return_if (!strlen(lp) || strlen(lp) > 270, -1);  /* 1-270 B */

    return evcoap_opt_add_string(pdu, EVCOAP_OPT_LOCATION_PATH, lp);
}

int evcoap_pdu_add_uri_port(struct evcoap_pdu *pdu, ev_uint16_t up)
{
    dbg_return_if (pdu == NULL, -1);
    /* 0-2 B length is enforced by 16-bit 'up'. */

    return evcoap_opt_add_uint(pdu, EVCOAP_OPT_URI_PORT, up);
}

int evcoap_pdu_add_location_query(struct evcoap_pdu *pdu, const char *lq)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (lq == NULL, -1);
    dbg_return_if (!strlen(lq) || strlen(lq) > 270, -1);  /* 1-270 B */

    return evcoap_opt_add_string(pdu, EVCOAP_OPT_LOCATION_QUERY, lq);
}

int evcoap_pdu_add_uri_path(struct evcoap_pdu *pdu, const char *up)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (up == NULL, -1);
    dbg_return_if (!strlen(up) || strlen(up) > 270, -1);  /* 1-270 B */

    return evcoap_opt_add_string(pdu, EVCOAP_OPT_URI_PATH, up);
}

int evcoap_pdu_add_token(struct evcoap_pdu *pdu, const ev_uint8_t *t,
        size_t t_len)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (t == NULL, -1);
    dbg_return_if (!t_len || t_len > 8, -1);  /* 1-8 B */

    return evcoap_opt_add_opaque(pdu, EVCOAP_OPT_TOKEN, t, t_len);
}

int evcoap_pdu_add_accept(struct evcoap_pdu *pdu, ev_uint16_t a)
{
    dbg_return_if (pdu == NULL, -1);
    /* 0-2 B length is enforced by 16-bit 'a'. */

    return evcoap_opt_add_uint(pdu, EVCOAP_OPT_ACCEPT, a);
}

int evcoap_pdu_add_if_match(struct evcoap_pdu *pdu, const ev_uint8_t *im,
        size_t im_len)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (im == NULL, -1);
    dbg_return_if (!im_len || im_len > 8, -1);  /* 1-8 B */

    return evcoap_opt_add_opaque(pdu, EVCOAP_OPT_IF_MATCH, im, im_len);
}

int evcoap_pdu_add_uri_query(struct evcoap_pdu *pdu, const char *uq)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (uq == NULL, -1);
    dbg_return_if (!strlen(uq) || strlen(uq) > 270, -1);  /* 1-270 B */

    return evcoap_opt_add_string(pdu, EVCOAP_OPT_URI_QUERY, uq);
}

int evcoap_pdu_add_if_none_match(struct evcoap_pdu *pdu)
{
    dbg_return_if (pdu == NULL, -1);

    return evcoap_opt_add_empty(pdu, EVCOAP_OPT_IF_NONE_MATCH);
}

int evcoap_pdu_add_observe(struct evcoap_pdu *pdu, ev_uint16_t o)
{
    dbg_return_if (pdu == NULL, -1);
    /* 0-2 B length is enforced by 16-bit 'o'. */

    return evcoap_opt_add_uint(pdu, EVCOAP_OPT_OBSERVE, o);
}

int evcoap_pdu_add_max_ofe(struct evcoap_pdu *pdu, ev_uint32_t mo)
{
    dbg_return_if (pdu == NULL, -1);
    /* 0-2 B length is enforced by 32-bit 'mo'. */

    return evcoap_opt_add_uint(pdu, EVCOAP_OPT_MAX_OFE, mo);
}

const char *evcoap_pdu_get_uri_host(struct evcoap_pdu *pdu)
{
    return evcoap_pdu_get_string_opt(pdu, EVCOAP_OPT_URI_HOST);
}

int evcoap_pdu_get_uri_port(struct evcoap_pdu *pdu, ev_uint16_t *port)
{
    ev_uint64_t ui;

    dbg_err_if (port == NULL);

    if (evcoap_pdu_get_uint_opt(pdu, EVCOAP_OPT_URI_PORT, &ui))
        goto err;

    *port = (ev_uint16_t) ui;

    return 0;
err:
    return -1;
}

const char *evcoap_pdu_get_proxy_uri(struct evcoap_pdu *pdu)
{
    return evcoap_pdu_get_string_opt(pdu, EVCOAP_OPT_PROXY_URI);
}

int evcoap_send_request(struct evcoap *coap, struct evcoap_pdu *pdu,
        void (*cb)(struct evcoap_pdu *, int, void *), void *cb_args,
        struct timeval *timeout)
{
    const char *host, *proxy_uri;
    char sport[6] = COAP_DEFAULT_SERVER_PORT_STR;
    ev_uint16_t port = 0;
    ev_uint8_t tok[8];
    struct evutil_addrinfo hints;
    struct evcoap_sendreq_args *sendreq_args = NULL;

    dbg_return_if (coap == NULL, -1);
    dbg_return_if (pdu == NULL, -1);

    /* Sanity check the supplied PDU. */
    dbg_err_if (evcoap_pdu_sanitize_send_req(coap, pdu));

    /* If there is no Token option, add one automatically. */
    if (!evcoap_opt_get(pdu, EVCOAP_OPT_TOKEN))
    {
        evutil_secure_rng_get_bytes(tok, sizeof tok);
        dbg_err_if (evcoap_pdu_add_token(pdu, tok, sizeof tok));
    }

    /* Try to get destination host and port:
     *  1) Proxy-Uri
     *  2) Uri-Host [+ Uri-Port] */
    if ((proxy_uri = evcoap_pdu_get_proxy_uri(pdu)))
    {
        const char *tmp;

        dbg_err_if (u_uri_crumble(proxy_uri, 0, &pdu->uri));
        dbg_err_if ((host = u_uri_get_host(pdu->uri)) == NULL);
        if ((tmp = u_uri_get_port(pdu->uri)) != NULL)
        {
            dbg_err_if (u_strlcpy(sport, tmp, sizeof sport));
        }
    }
    else
    {
        /* If there is no Proxy-Uri option, then assume Uri-Host. */
        dbg_err_if ((host = evcoap_pdu_get_uri_host(pdu)) == NULL);
        if (evcoap_pdu_get_uri_port(pdu, &port) == 0)
        {
            dbg_err_if (u_snprintf(sport, sizeof sport, "%u", port));
        }
    }
    
    /* Frame everything needed to push the request forward into a struct
     * evcoap_sendreq_args (MUST BE free'd by evcoap_sendreq_dns_cb.) */
    dbg_err_if ((sendreq_args = evcoap_sendreq_args_new(coap, pdu, cb, cb_args, 
                    timeout)) == NULL);

    /* Set up hints needed by evdns_getaddrinfo(). */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = 0;

    /* Pass the ball to evdns.  In case the evdns resolved immediately,
     * we return the send operation status hold by pdu->send_status.
     * Otherwise return ok and let the status of the send operation be 
     * given back to the user supplied callback.
     * Save the evdns_getaddrinfo_request pointer (may be NULL in case
     * of immediate resolution) so that the request can be canceled 
     * in a later moment if needed. */
    pdu->gai_req = evdns_getaddrinfo(coap->dns, host, sport, &hints, 
            evcoap_sendreq_dns_cb, sendreq_args);

    return pdu->send_status;
err:
    return -1;
}

int evcoap_pdu_req_set_header(struct evcoap_pdu *pdu,
        evcoap_pdu_type_t pdu_type, evcoap_method_t method)
{
    dbg_return_if (pdu == NULL, -1); 
    dbg_return_if (!EVCOAP_PDU_TYPE_VALID(pdu_type), -1);
    dbg_return_if (!EVCOAP_METHOD_VALID(method), -1);

    /* CoAP protocol version is set by PDU the sanitizer. */
    pdu->t = pdu_type;
    /* OC is set by the option encoder. */
    pdu->code = method;
    /* MID is set by the PDU sanitizer. */


    return 0;
}

/* 'pdu_type' == CON|NON|RST|ACK */
/* 'resp_code' == one of EVCOAP_RESP_CODE_* */
/* 'message_id' == mid or EVCOAP_MID_AUTO if user lets evcoap pick one. */
int evcoap_pdu_resp_set_header(struct evcoap_pdu *pdu,
        evcoap_pdu_type_t pdu_type, evcoap_resp_code_t resp_code, 
        ev_uint16_t message_id)
{
    dbg_return_if (pdu == NULL, -1); 
    dbg_return_if (!EVCOAP_PDU_TYPE_VALID(pdu_type), -1);

    pdu->ver = COAP_PROTO_VER_1;
    pdu->t = pdu_type;
    /* OC is set by the option encoder. */
    pdu->code = resp_code;
//    pdu->mid = (message_id == EVCOAP_MID_AUTO) ? evcoap_gen_mid() : message_id;

    return 0;
}
