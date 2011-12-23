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
ec_client_t *ec_request_new(ec_t *coap, ec_method_t m, const char *uri, 
        ec_msg_model_t mm)
{
    return ec_client_new(coap, m, uri, mm, NULL, 0);
}

/**
 *  \brief  TODO
 */
ec_client_t *ec_proxy_request_new(ec_t *coap, ec_method_t m, const char *uri,
        ec_msg_model_t mm, const char *proxy_host, ev_uint16_t proxy_port)
{
    return ec_client_new(coap, m, uri, mm, proxy_host, proxy_port);
}

/**
 *  \brief  TODO
 *
 *  \param  cli     ...
 *  \param  cb      optional callback that will be invoked on response or error 
 *  \param  cb_args optional arguments to the callback 
 */
int ec_request_send(ec_client_t *cli, ec_client_cb_t cb, void *cb_args)
{
    dbg_return_if (cli == NULL, -1);

    return ec_client_go(cli, cb, cb_args);
}

/**
 *  \brief  TODO
 */
int ec_bind_socket(ec_t *coap, const char *addr, ev_uint16_t port)
{
    evutil_socket_t sd = (evutil_socket_t) -1;
    char addrport[1024] = { '\0' };
    struct sockaddr_storage ss;
    int ss_len = sizeof ss;

    dbg_return_if (coap == NULL, -1);
    dbg_return_if (addr == NULL, -1);

    if (port == 0)
        port = EC_DEFAULT_PORT;

    dbg_err_if (u_snprintf(addrport, sizeof addrport, "%s:%u", addr, port));

    dbg_err_ifm (evutil_parse_sockaddr_port(addrport, (struct sockaddr *) &ss,
                &ss_len), "Error parsing %s", addrport);

    dbg_err_ifm ((sd = ec_net_bind_socket(&ss, ss_len)) == -1, 
            "Error binding %s", addrport);

    dbg_err_sif (evutil_make_socket_nonblocking(sd));

    /* TODO add to servers. */

    return 0;
err:
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

    ec_flow_t *flow = &srv->flow;

    flow->resp_code = rc;

    return -1;
}

/**
 *  \brief  TODO
 */
int ec_request_add_content_type(ec_client_t *cli, ev_uint16_t ct)
{
    dbg_return_if (cli == NULL, -1);

    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_content_type(opts, ct);
}

/**
 *  \brief  TODO
 */
int ec_request_add_max_age(ec_client_t *cli, ev_uint32_t ma)
{
    dbg_return_if (cli == NULL, -1);

    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_max_age(opts, ma);
}

/**
 *  \brief  TODO
 */
int ec_request_add_proxy_uri(ec_client_t *cli, const char *pu)
{
    dbg_return_if (cli == NULL, -1);

    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_proxy_uri(opts, pu);
}

/**
 *  \brief  TODO
 */
int ec_request_add_etag(ec_client_t *cli, const ev_uint8_t *et, size_t et_len)
{
    dbg_return_if (cli == NULL, -1);
    
    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_etag(opts, et, et_len);
}

/**
 *  \brief  TODO
 */
int ec_request_add_uri_host(ec_client_t *cli, const char  *uh)
{
    dbg_return_if (cli == NULL, -1);
    
    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_uri_host(opts, uh);
}

/**
 *  \brief  TODO
 */
int ec_request_add_location_path(ec_client_t *cli, const char *lp)
{
    dbg_return_if (cli == NULL, -1);
    
    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_location_path(opts, lp);
}

/**
 *  \brief  TODO
 */
int ec_request_add_uri_port(ec_client_t *cli, ev_uint16_t up)
{
    dbg_return_if (cli == NULL, -1);
    
    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_uri_port(opts, up);
}

/**
 *  \brief  TODO
 */
int ec_request_add_location_query(ec_client_t *cli, const char *lq)
{
    dbg_return_if (cli == NULL, -1);
    
    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_location_query(opts, lq);
}

/**
 *  \brief  TODO
 */
int ec_request_add_uri_path(ec_client_t *cli, const char *up)
{
    dbg_return_if (cli == NULL, -1);
    
    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_uri_path(opts, up);
}

/**
 *  \brief  TODO
 */
int ec_request_add_token(ec_client_t *cli, const ev_uint8_t *t, size_t t_len)
{
    dbg_return_if (cli == NULL, -1);
    
    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_token(opts, t, t_len);
}

/**
 *  \brief  TODO
 */
int ec_request_add_accept(ec_client_t *cli, ev_uint16_t a)
{
    dbg_return_if (cli == NULL, -1);
    
    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_accept(opts, a);
}

/**
 *  \brief  TODO
 */
int ec_request_add_if_match(ec_client_t *cli, const ev_uint8_t *im, 
        size_t im_len)
{
    dbg_return_if (cli == NULL, -1);
    
    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_if_match(opts, im, im_len);
}

/**
 *  \brief  TODO
 */
int ec_request_add_uri_query(ec_client_t *cli, const char *uq)
{
    dbg_return_if (cli == NULL, -1);
    
    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_uri_query(opts, uq);
}

/**
 *  \brief  TODO
 */
int ec_request_add_if_none_match(ec_client_t *cli)
{
    dbg_return_if (cli == NULL, -1);
    
    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_if_none_match(opts);
}

/**
 *  \brief  TODO
 */
int ec_request_add_observe(ec_client_t *cli, ev_uint16_t o)
{
    dbg_return_if (cli == NULL, -1);
    
    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_observe(opts, o);
}

/**
 *  \brief  TODO
 */
int ec_request_add_max_ofe(ec_client_t *cli, ev_uint32_t mo)
{
    dbg_return_if (cli == NULL, -1);
    
    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_max_ofe(opts, mo);
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
