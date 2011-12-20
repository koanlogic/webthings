#include <u/libu.h>
#include "evcoap.h"

/**
 *  \brief  TODO
 */
ec_t *ec_init(struct event_base *base, struct evdns_base *dns)
{
    ec_t *coap = NULL;

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
int ec_loopexit(ec_t *coap, const struct timeval *tv)
{
    return event_base_loopexit(coap->base, tv);
}

/**
 *  \brief  TODO
 */
int ec_loopbreak(ec_t *coap)
{
    return event_base_loopbreak(coap->base);
}

/**
 *  \brief  TODO
 */
ec_client_t *ec_new_request(ec_method_t m, const char *uri)
{
    return ec_client_new(m, uri, NULL, 0);
}

/**
 *  \brief  TODO
 */
ec_client_t *ec_new_proxy_request(ec_method_t m, const char *uri,
        const char *proxy_host, ev_uint16_t proxy_port)
{
    return ec_client_new(m, uri, proxy_host, proxy_port);
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
int ec_request_set_payload(ec_client_t *cli, ev_uint8_t *payload, size_t sz)
{
    dbg_return_if (cli == NULL, -1);

    ec_pdu_t *req = &cli->req;

    return ec_pdu_set_payload(req, payload, sz);
}

/**
 *  \brief  TODO (user may set a custom response code.)
 */
int ec_response_set_code(ec_server_t *srv, ec_rc_t rc)
{
    dbg_return_if (srv == NULL, -1);
    dbg_return_if (!EC_IS_RESP_CODE(rc), -1);

    ec_txn_t *meta = &srv->meta;

    meta->resp_code = rc;

    return -1;
}

/**
 *  \brief  TODO (user may set a custom content type.)
 */
int ec_request_add_content_type(ec_client_t *cli, ev_uint16_t ct)
{
    dbg_return_if (cli == NULL, -1);

    /* Valid range is 0-65535.
     * EC_CT_* enum values are provided for registered content types.
     * 0-2 B length is enforced by 16-bit 'ct'. */

    ec_pdu_t *req = &cli->req;

    return ec_opt_add_uint(&req->opts, EC_OPT_CONTENT_TYPE, ct);
}

/**
 *  \brief  TODO
 */
int ec_request_add_max_age(ec_client_t *cli, ev_uint32_t ma)
{
    dbg_return_if (cli == NULL, -1);

    /* 0-4 B lenght is enforced by 32-bit 'ma'. */

    ec_pdu_t *req = &cli->req;

    return ec_opt_add_uint(&req->opts, EC_OPT_MAX_AGE, ma);
}

/**
 *  \brief  TODO
 */
int ec_request_add_proxy_uri(ec_client_t *cli, const char *pu)
{
    dbg_return_if (cli == NULL, -1);
    dbg_return_if (pu == NULL, -1);
    dbg_return_if (!strlen(pu) || strlen(pu) > 270, -1); /* 1-270 B */

    ec_pdu_t *req = &cli->req;

    return ec_opt_add_string(&req->opts, EC_OPT_PROXY_URI, pu);
}

/**
 *  \brief  TODO
 */
int ec_request_add_etag(ec_client_t *cli, const ev_uint8_t *et, size_t et_len)
{
    dbg_return_if (cli == NULL, -1);
    dbg_return_if (et == NULL, -1);
    dbg_return_if (!et_len || et_len > 8, -1);  /* 1-8 B */

    ec_pdu_t *req = &cli->req;

    return ec_opt_add_opaque(&req->opts, EC_OPT_ETAG, et, et_len);
}

/**
 *  \brief  TODO
 */
int ec_request_add_uri_host(ec_client_t *cli, const char  *uh)
{
    dbg_return_if (cli == NULL, -1);
    dbg_return_if (uh == NULL, -1);
    dbg_return_if (!strlen(uh) || strlen(uh) > 270, -1);  /* 1-270 B */

    ec_pdu_t *req = &cli->req;

    return ec_opt_add_string(&req->opts, EC_OPT_URI_HOST, uh);
}

/**
 *  \brief  TODO
 */
int ec_request_add_location_path(ec_client_t *cli, const char *lp)
{
    dbg_return_if (cli == NULL, -1);
    dbg_return_if (lp == NULL, -1);
    dbg_return_if (!strlen(lp) || strlen(lp) > 270, -1);  /* 1-270 B */

    ec_pdu_t *req = &cli->req;

    return ec_opt_add_string(&req->opts, EC_OPT_LOCATION_PATH, lp);
}

/**
 *  \brief  TODO
 */
int ec_request_add_uri_port(ec_client_t *cli, ev_uint16_t up)
{
    dbg_return_if (cli == NULL, -1);
    /* 0-2 B length is enforced by 16-bit 'up'. */

    ec_pdu_t *req = &cli->req;

    return ec_opt_add_uint(&req->opts, EC_OPT_URI_PORT, up);
}

/**
 *  \brief  TODO
 */
int ec_request_add_location_query(ec_client_t *cli, const char *lq)
{
    dbg_return_if (cli == NULL, -1);
    dbg_return_if (lq == NULL, -1);
    dbg_return_if (!strlen(lq) || strlen(lq) > 270, -1);  /* 1-270 B */

    ec_pdu_t *req = &cli->req;

    return ec_opt_add_string(&req->opts, EC_OPT_LOCATION_QUERY, lq);
}

/**
 *  \brief  TODO
 */
int ec_request_add_uri_path(ec_client_t *cli, const char *up)
{
    dbg_return_if (cli == NULL, -1);
    dbg_return_if (up == NULL, -1);
    dbg_return_if (!strlen(up) || strlen(up) > 270, -1);  /* 1-270 B */

    ec_pdu_t *req = &cli->req;

    return ec_opt_add_string(&req->opts, EC_OPT_URI_PATH, up);
}

/**
 *  \brief  TODO
 */
int ec_request_add_token(ec_client_t *cli, const ev_uint8_t *t, size_t t_len)
{
    dbg_return_if (cli == NULL, -1);
    dbg_return_if (t == NULL, -1);
    dbg_return_if (!t_len || t_len > 8, -1);  /* 1-8 B */

    ec_pdu_t *req = &cli->req;

    return ec_opt_add_opaque(&req->opts, EC_OPT_TOKEN, t, t_len);
}

/**
 *  \brief  TODO
 */
int ec_request_add_accept(ec_client_t *cli, ev_uint16_t a)
{
    dbg_return_if (cli == NULL, -1);
    /* 0-2 B length is enforced by 16-bit 'a'. */

    ec_pdu_t *req = &cli->req;

    return ec_opt_add_uint(&req->opts, EC_OPT_ACCEPT, a);
}

/**
 *  \brief  TODO
 */
int ec_request_add_if_match(ec_client_t *cli, const ev_uint8_t *im, 
        size_t im_len)
{
    dbg_return_if (cli == NULL, -1);
    dbg_return_if (im == NULL, -1);
    dbg_return_if (!im_len || im_len > 8, -1);  /* 1-8 B */

    ec_pdu_t *req = &cli->req;

    return ec_opt_add_opaque(&req->opts, EC_OPT_IF_MATCH, im, im_len);
}

/**
 *  \brief  TODO
 */
int ec_request_add_uri_query(ec_client_t *cli, const char *uq)
{
    dbg_return_if (cli == NULL, -1);
    dbg_return_if (uq == NULL, -1);
    dbg_return_if (!strlen(uq) || strlen(uq) > 270, -1);  /* 1-270 B */

    ec_pdu_t *req = &cli->req;

    return ec_opt_add_string(&req->opts, EC_OPT_URI_QUERY, uq);
}

/**
 *  \brief  TODO
 */
int ec_request_add_if_none_match(ec_client_t *cli)
{
    dbg_return_if (cli == NULL, -1);

    ec_pdu_t *req = &cli->req;

    return ec_opt_add_empty(&req->opts, EC_OPT_IF_NONE_MATCH);
}

/**
 *  \brief  TODO
 */
int ec_request_add_observe(ec_client_t *cli, ev_uint16_t o)
{
    dbg_return_if (cli == NULL, -1);
    /* 0-2 B length is enforced by 16-bit 'o'. */

    ec_pdu_t *req = &cli->req;

    return ec_opt_add_uint(&req->opts, EC_OPT_OBSERVE, o);
}

/**
 *  \brief  TODO
 */
int ec_request_add_max_ofe(ec_client_t *cli, ev_uint32_t mo)
{
    dbg_return_if (cli == NULL, -1);
    /* 0-2 B length is enforced by 32-bit 'mo'. */

    ec_pdu_t *req = &cli->req;

    return ec_opt_add_uint(&req->opts, EC_OPT_MAX_OFE, mo);
}

/**
 *  \brief  TODO
 */
int ec_response_set_payload(ec_server_t *srv, ev_uint8_t *payload, size_t sz)
{
    dbg_return_if (srv == NULL, -1);

    ec_pdu_t *res = &srv->res;

    return ec_pdu_set_payload(res, payload, sz);
}

/**
 *  \brief  TODO
 */
int ec_update_representation(const char *uri, const ev_uint8_t *rep,
        size_t rep_len, ec_mt_t media_type)
{
    return -1;
}

