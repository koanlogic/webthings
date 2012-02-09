#include <u/libu.h>
#include <event2/util.h>
#include "evcoap.h"
#include "evcoap_cli.h"
#include "evcoap_srv.h"
#include "evcoap_net.h"
#include "evcoap_opt.h"

static ec_resource_t *ec_resource_new(const char *url, ec_server_cb_t cb,
        void *args);
static void ec_resource_free(ec_resource_t *r);

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

    TAILQ_INIT(&coap->clients);
    TAILQ_INIT(&coap->servers);
    TAILQ_INIT(&coap->listeners);
    TAILQ_INIT(&coap->resources);

    dbg_err_if (ec_dups_init(coap, &coap->dups));
    dbg_err_if (ec_cfg_init(&coap->cfg));

    return coap;
err:
    return NULL;
}

/**
 *  \brief  TODO
 */
void ec_term(ec_t *coap)
{
    if (coap)
    {
        ec_dups_term(&coap->dups);
        /* TODO */
        u_free(coap);
    }

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
    return ec_client_new(coap, m, uri, mm, NULL, (uint16_t) 0);
}

/**
 *  \brief  TODO
 */
ec_client_t *ec_proxy_request_new(ec_t *coap, ec_method_t m, const char *uri,
        ec_msg_model_t mm, const char *proxy_host, uint16_t proxy_port)
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
int ec_request_send(ec_client_t *cli, ec_client_cb_t cb, void *cb_args,
        struct timeval *tout)
{
    dbg_return_if (cli == NULL, -1);

    return ec_client_go(cli, cb, cb_args, tout);
}

/**
 *  \brief  TODO
 */
int ec_bind_socket(ec_t *coap, const char *addr, uint16_t port)
{
    evutil_socket_t sd = (evutil_socket_t) -1;
    char addrport[1024] = { '\0' };
    struct sockaddr_storage ss;
    int ss_len = sizeof ss;

    dbg_return_if (coap == NULL, -1);
    dbg_return_if (addr == NULL, -1);

    dbg_err_if (u_snprintf(addrport, sizeof addrport, "%s:%u", 
                addr, !port ? EC_COAP_DEFAULT_PORT : port));

    dbg_err_ifm (evutil_parse_sockaddr_port(addrport, (struct sockaddr *) &ss,
                &ss_len), "Error parsing %s", addrport);

    dbg_err_ifm ((sd = ec_net_bind_socket(&ss, ss_len)) == -1, 
            "Error binding %s", addrport);

    /* Make bound socket non-blocking. */
    dbg_err_sif (evutil_make_socket_nonblocking(sd));

    /* Register a listener. */
    dbg_err_if (ec_listeners_add(coap, sd));

    return 0;
err:
    if (sd != -1)
        evutil_closesocket(sd);
    return -1;
}

/**
 *  \brief  TODO
 */
int ec_register_fb(ec_t *coap, ec_server_cb_t fb, void *fb_args)
{
    dbg_return_if (coap == NULL, -1);

    coap->fb = fb;
    coap->fb_args = fb_args;

    return 0;
}

/**
 *  \brief  TODO
 */
int ec_request_set_payload(ec_client_t *cli, uint8_t *payload, size_t sz)
{
    dbg_return_if (cli == NULL, -1);

    /* Check if Block fragmentation is needed.
     * In case it were not handled transparently, check that the supplied 
     * payload fits in the currently set upper bound. */
    size_t bsz;

    dbg_err_if (ec_get_block_size(cli->base, &bsz));
    dbg_err_ifm (bsz && sz > bsz,
            "payload would be fragmented (Block must be handled manually !)");

    ec_pdu_t *req = &cli->req;

    return ec_pdu_set_payload(req, payload, sz);
err:
    return -1;
}

/**
 *  \brief  Retrieve all media types that the client is willing to Accept.
 *  
 *  \param  mta     pointer to the media-types array
 *  \param  mta_sz  value-result argument
 */ 
int ec_request_get_acceptable_media_types(ec_server_t *srv, ec_mt_t *mta,
        size_t *mta_sz)
{
    ec_pdu_t *req;

    dbg_return_if (srv == NULL, -1);
    dbg_return_if ((req = srv->req) == NULL, -1);

    ec_opts_t *opts = &req->opts;

    return ec_opts_get_accept_all(opts, mta, mta_sz);
}

/**
 *  \brief  TODO (user may set a custom response code.)
 */
int ec_response_set_code(ec_server_t *srv, ec_rc_t rc)
{
    dbg_return_if (srv == NULL, -1);

    return ec_flow_set_resp_code(&srv->flow, rc); 
}

/**
 *  \brief  TODO
 */
ec_rc_t ec_response_get_code(ec_client_t *cli)
{
    dbg_return_if (cli == NULL, -1);

    return ec_flow_get_resp_code(&cli->flow);
}

int ec_response_get_content_type(ec_client_t *cli, ec_mt_t *ct)
{
    ec_opts_t *opts;

    dbg_return_if (cli == NULL, -1);

    nop_err_if ((opts = ec_client_get_response_options(cli)) == NULL);

    return ec_opts_get_content_type(opts, (uint16_t *) ct);
err:
    return -1;
}

int ec_response_get_block1(ec_client_t *cli, uint32_t *bnum, bool *more,
        size_t *bsz)
{
    uint8_t szx;
    ec_opts_t *opts;

    dbg_return_if (cli == NULL, -1);
    dbg_return_if (bsz == NULL, -1);

    nop_err_if ((opts = ec_client_get_response_options(cli)) == NULL);
    nop_err_if (ec_opts_get_block1(opts, bnum, more, &szx));

    *bsz = 1 << (szx + 4);

err:
    return -1;
}

int ec_response_get_block2(ec_client_t *cli, uint32_t *bnum, bool *more,
        size_t *bsz)
{
    uint8_t szx;
    ec_opts_t *opts;

    dbg_return_if (cli == NULL, -1);
    dbg_return_if (bsz == NULL, -1);

    nop_err_if ((opts = ec_client_get_response_options(cli)) == NULL);
    nop_err_if (ec_opts_get_block2(opts, bnum, more, &szx));

    *bsz = 1 << (szx + 4);

err:
    return -1;
}

/* Works for unicast exchanges only. */
uint8_t *ec_response_get_payload(ec_client_t *cli, size_t *sz)
{
    ec_pdu_t *res;

    dbg_return_if (cli == NULL, NULL);
    dbg_return_if (sz == NULL, NULL);

    dbg_err_if ((res = ec_client_get_response_pdu(cli)) == NULL);

    /* Return payload and size. */
    *sz = res->payload_sz;

    return res->payload;
err:
    return NULL;
}

/**
 *  \brief  TODO
 */
int ec_request_add_content_type(ec_client_t *cli, uint16_t ct)
{
    dbg_return_if (cli == NULL, -1);

    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_content_type(opts, ct);
}

/**
 *  \brief  TODO
 */
int ec_request_add_max_age(ec_client_t *cli, uint32_t ma)
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
int ec_request_add_etag(ec_client_t *cli, const uint8_t *et, size_t et_len)
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
int ec_request_add_uri_port(ec_client_t *cli, uint16_t up)
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
int ec_request_add_token(ec_client_t *cli, const uint8_t *t, size_t t_len)
{
    dbg_return_if (cli == NULL, -1);
    
    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_token(opts, t, t_len);
}

/**
 *  \brief  TODO
 */
int ec_request_add_accept(ec_client_t *cli, uint16_t a)
{
    dbg_return_if (cli == NULL, -1);
    
    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_accept(opts, a);
}

/**
 *  \brief  TODO
 */
int ec_request_add_if_match(ec_client_t *cli, const uint8_t *im, 
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
int ec_request_add_observe(ec_client_t *cli, uint16_t o)
{
    dbg_return_if (cli == NULL, -1);
    
    ec_opts_t *opts = &cli->req.opts;

    return ec_opts_add_observe(opts, o);
}

/**
 *  \brief  TODO
 */
int ec_response_set_payload(ec_server_t *srv, uint8_t *payload, size_t sz)
{
    dbg_return_if (srv == NULL, -1);

    ec_pdu_t *res = srv->res;

    return ec_pdu_set_payload(res, payload, sz);
}

/**
 *  \brief  TODO
 */
int ec_response_add_etag(ec_server_t *srv, const uint8_t *et, size_t et_len)
{
    ec_pdu_t *res;

    dbg_return_if (srv == NULL, -1);
    dbg_return_if ((res = srv->res) == NULL, -1);

    ec_opts_t *opts = &res->opts;

    return ec_opts_add_etag(opts, et, et_len);
}

/**
 *  \brief  TODO
 */
int ec_response_add_content_type(ec_server_t *srv, uint16_t ct)
{
    ec_pdu_t *res;

    dbg_return_if (srv == NULL, -1);
    dbg_return_if ((res = srv->res) == NULL, -1);

    ec_opts_t *opts = &res->opts;

    return ec_opts_add_content_type(opts, ct);
}

/**
 *  \brief  TODO
 */
int ec_update_representation(const char *uri, const uint8_t *rep,
        size_t rep_len, ec_mt_t media_type)
{
    return -1;
}

/**
 *  \brief  TODO
 */ 
int ec_register_cb(ec_t *coap, const char *url, ec_server_cb_t cb, void *args)
{
    ec_resource_t *tmp, *r;

    dbg_return_if (coap == NULL, -1);
    dbg_return_if (url == NULL, -1);
    dbg_return_if (cb == NULL, -1);

    TAILQ_FOREACH(tmp, &coap->resources, next)
    {
        dbg_err_ifm (!evutil_ascii_strcasecmp(tmp->path, url),
                "%s already registered", url);
    }

    /* Create a new resource record and stick it to the global context. */
    dbg_err_sif ((r = ec_resource_new(url, cb, args)) == NULL);

    TAILQ_INSERT_TAIL(&coap->resources, r, next);

    return 0;
err:
    if (r)
        ec_resource_free(r);
    return -1;
}

/* Supplying val=0 means unlimited (bounded only by lower layer protocols.) */
int ec_set_block_size(ec_t *coap, size_t val)
{
    dbg_return_if (coap == NULL, -1);

    return ec_cfg_set_block_sz(&coap->cfg, val);
}

int ec_get_block_size(ec_t *coap, size_t *val)
{
    uint8_t szx;
    bool is_stateless;

    dbg_return_if (coap == NULL, -1);
    dbg_return_if (val == NULL, -1);

    dbg_err_if (ec_cfg_get_block_info(&coap->cfg, &is_stateless, &szx));

    *val = is_stateless ? 0 : 1 << (szx + 4);

    return 0;
err:
    return -1;
}

static ec_resource_t *ec_resource_new(const char *url, ec_server_cb_t cb,
        void *args)
{
    ec_resource_t *r = NULL;

    dbg_err_sif ((r = u_zalloc(sizeof *r)) == NULL);
    dbg_err_sif ((r->path = u_strdup(url)) == NULL);
    r->cb = cb;
    r->cb_args = args;

    return r;
err:
    if (r)
        u_free(r);
    return NULL;
}

static void ec_resource_free(ec_resource_t *r)
{
    if (r)
    {
        if (r->path)
            u_free(r->path);
        u_free(r);
    }
}
