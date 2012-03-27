#include <unistd.h>
#include <getopt.h>
#include <strings.h>
#include <evcoap.h>
#include <u/libu.h>

#include "evcoap_filesys.h"
#include "evcoap_observe.h"

int facility = LOG_LOCAL0;

#define CHAT(...)   do { if (g_ctx.verbose) u_con(__VA_ARGS__); } while (0)
#define DEFAULT_CONF    "./coap-server.conf"

typedef struct
{
    uint32_t bnum;
    bool more;
    size_t bsz;
} blockopt_t;

typedef struct
{
    ec_t *coap;
    struct event_base *base;
    struct evdns_base *dns;
    const char *conf;
    ec_filesys_t *fs;
    size_t bsz;
    bool verbose;
    bool rel_refs;
    struct timeval sep;
    blockopt_t b1;
    u_buf_t *resbuf;
} ctx_t;

ctx_t g_ctx =
{
    .coap = NULL,
    .base = NULL,
    .dns = NULL,
    .conf = DEFAULT_CONF,
    .fs = NULL,
    .bsz = 0,  /* By default Block is fully under user control. */
    .verbose = false,
    .rel_refs = false,
    .sep = { .tv_sec = 0, .tv_usec = 0 },
    .b1 = { .bnum = 0, .more = false, .bsz = 0 },
    .resbuf = NULL
};

int server_init(void);
void server_term(void);
int server_run(void);
int server_bind(u_config_t *cfg);

int vhost_setup(u_config_t *vhost);
int vhost_load_contents(u_config_t *vhost, const char *origin);
int vhost_load_resource(u_config_t *res, const char *origin);
int vhost_load_resource_attrs(ec_res_t *res, u_config_t *attrs);
int vhost_load_allowed_methods(const char *m, ec_method_mask_t *pmm);

int parse_addr(const char *ap, char *a, size_t a_sz, uint16_t *p);
int normalize_origin(const char *o, char co[U_URI_STRMAX]);

ec_cbrc_t serve(ec_server_t *srv, void *u0, struct timeval *u1, bool u2);
ec_cbrc_t create(ec_server_t *srv, void *u0, struct timeval *u1, bool u2);

int serve_wkc(ec_server_t *srv, ec_method_t method);
int serve_get(ec_server_t *srv, ec_rep_t *rep);
int serve_delete(ec_server_t *srv, const char *uri);
int serve_put(ec_server_t *srv, ec_rep_t *rep);
int serve_post(ec_server_t *srv);

void usage(const char *prog);


int main(int ac, char *av[])
{
    int c, i;
    u_config_t *cfg = NULL, *vhost;

    while ((c = getopt(ac, av, "b:hf:Rs:v")) != -1)
    {
        switch (c)
        {
            case 'b':
                if (sscanf(optarg, "%zu", &g_ctx.bsz) != 1)
                    usage(av[0]);
                break;
            case 'f':
                g_ctx.conf = optarg;
                break;
            case 'v':
                g_ctx.verbose = true;
                break;
            case 's':
                if (sscanf(optarg, "%lld", (long long *)&g_ctx.sep.tv_sec) != 1)
                    usage(av[0]);
                break;
            case 'R':
                g_ctx.rel_refs = true;
                break;
            case 'h':
            default:
                usage(av[0]);
        }
    }

    /* Load configuration from file. */
    con_err_ifm(u_config_load_from_file(g_ctx.conf, &cfg),
            "error loading %s", g_ctx.conf);

    /* Initialize libevent and evcoap machinery. */
    con_err_ifm(server_init(), "evcoap initialization failed");

    /* Bind configured addresses. */
    con_err_ifm(server_bind(cfg), "server socket setup failed");

    /* Setup configured virtual hosts. */
    for (i = 0; (vhost = u_config_get_child_n(cfg, "vhost", i)) != NULL; ++i)
        con_err_ifm(vhost_setup(vhost), "configuration error");
    con_err_ifm(i == 0, "no origins configured");

    /* Attach create() as the URI fallback handler. */
    con_err_ifm(ec_register_fb(g_ctx.coap, create, NULL),
            "error registering fallback");

    con_err_ifm(server_run(), "server run failed");

    return EXIT_SUCCESS;
err:
    if (cfg)
        u_config_free(cfg);
    server_term();

    return EXIT_FAILURE;
}

int vhost_setup(u_config_t *vhost)
{
    int i;
    u_config_t *origin;
    const char *o;
    char co[U_URI_STRMAX];

    dbg_return_if(vhost == NULL, -1);

    /* For each origin specified for this vhost... */
    for (i = 0;
            (origin = u_config_get_child_n(vhost, "origin", i)) != NULL;
            ++i)
    {
        /* Get and check origin. */
        con_err_ifm((o = u_config_get_value(origin)) == NULL,
                "missing origin value !");

        con_err_ifm(normalize_origin(o, co), "origin check failed");

        /* Load contents. */
        con_err_ifm(vhost_load_contents(vhost, co), "could not load contents");
    }

    return 0;
err:
    return -1;
}

int normalize_origin(const char *o, char co[U_URI_STRMAX])
{
    u_uri_t *u = NULL;
    const char *scheme, *port;

    dbg_return_if(o == NULL || o[0] == '\0', -1);
    dbg_return_if(co == NULL, -1);

    con_err_ifm(u_uri_crumble(o, 0, &u), "%s parse error", o);

    /* Check that scheme is 'coap' or 'coaps'. */
    con_err_ifm((scheme = u_uri_get_scheme(u)) == NULL ||
            (strcasecmp(scheme, "coap") && strcasecmp(scheme, "coaps")),
            "bad %s scheme", scheme);

    /* Set default port if empty. */
    if ((port = u_uri_get_port(u)) == NULL || *port == '\0')
        (void) u_uri_set_port(u, EC_COAP_DEFAULT_SPORT);

    con_err_ifm(u_uri_knead(u, co), "error normalizing origin (%s)", o);

    u_uri_free(u), u = NULL;

    return 0;
err:
    if (u)
        u_uri_free(u);
    return -1;
}

int vhost_load_contents(u_config_t *vhost, const char *origin)
{
    size_t i;
    char wkc[1024] = { '\0' };
    u_config_t *res, *contents;

    dbg_return_if(vhost == NULL, -1);
    dbg_return_if(origin == NULL, -1);

    /* Pick up the "contents" section. */
    con_err_ifm(u_config_get_subkey(vhost, "contents", &contents),
            "no contents in virtual host !");

    /* Load hosted resources. */
    for (i = 0;
            (res = u_config_get_child_n(contents, "resource", i)) != NULL;
            ++i)
    {
        con_err_ifm(vhost_load_resource(res, origin),
                "error loading resource");
    }

    con_err_ifm(i == 0, "no resources in virtual host");

    /* Add the default /.well-known/core interface. */
    con_err_if(u_snprintf(wkc, sizeof wkc, "%s/.well-known/core", origin));
    CHAT("adding resource %s (AUTO)", wkc);
    con_err_ifm(ec_register_cb(g_ctx.coap, wkc, serve, NULL),
            "registering callback for %s failed", wkc);

    return 0;
err:
    return -1;
}

int vhost_load_resource(u_config_t *resource, const char *origin)
{
    int tmp;
    size_t i, val_sz;
    uint32_t ma;
    const char *path, *max_age, *val, *meth;
    ec_res_t *res = NULL;
    ec_mt_t mt;
    char uri[512];
    ec_method_mask_t methods;
    u_config_t *repr, *attrs;

    dbg_return_if(resource == NULL, -1);

    /* Get resource path. */
    con_err_ifm((path = u_config_get_subkey_value(resource, "path")) == NULL,
            "missing mandatory \'path\' in resource");

    /* Get resource max age (default to 60 secs if not specified.) */
    if ((max_age = u_config_get_subkey_value(resource, "max-age")) == NULL)
        ma = 60;
    else
    {
        con_err_ifm(u_atoi(max_age, &tmp), "conversion error for %s", max_age);
        ma = (uint32_t) tmp;
    }

    /* Get allowed methods. */
    if ((meth = u_config_get_subkey_value(resource, "allowed-methods")) == NULL)
        methods = EC_GET_MASK; /* Default is read-only. */
    else
    {
        con_err_ifm(vhost_load_allowed_methods(meth, &methods),
                "bad allowed-methods in %s%s", origin, path);
    }

    /* Create complete resource name. */
    con_err_ifm(u_snprintf(uri, sizeof uri, "%s%s", origin, path),
            "could not create uri for path %s and origin %s", path, origin);

    CHAT("adding resource %s", uri);

    /* Create FS resource. */
    con_err_ifm((res = ec_resource_new(uri, methods, ma)) == NULL,
            "resource creation failed");

    /* Load each resource representation. */
    for (i = 0; (repr = u_config_get_child_n(resource,
            "representation", i)) != NULL; ++i)
    {
        /* Retrieve representation type and value. */
        con_err_ifm(ec_mt_from_string(u_config_get_subkey_value(repr, "t:"),
                &mt), "media type map error");

        con_err_ifm((val = u_config_get_subkey_value(repr, "v:")) == NULL,
                "no value for resource %s", uri);
        val_sz = strlen(val);

        con_err_ifm(ec_resource_add_rep(res, (const uint8_t *) val,
                val_sz, mt, NULL),
                "error adding representation for %s", uri);
    }
    con_err_ifm(i == 0, "no resources in virtual host");

    /* Add fixed link-format attributes. */
    if (u_config_get_subkey(resource, "link-attrs", &attrs) == 0)
    {
        con_err_ifm(vhost_load_resource_attrs(res, attrs),
                "error loading link-attrs for resource %s%s", origin, path);
    }

    /* Put resource into the file system. */
    con_err_ifm(ec_filesys_put_resource(g_ctx.fs, res),
            "adding resource failed");
    res = NULL; /* ownership lost */

    /* Register the callback that will serve this URI. */
    con_err_ifm(ec_register_cb(g_ctx.coap, uri, serve, NULL),
            "registering callback for %s failed", uri);

    return 0;
err:
    if (res)
        ec_resource_free(res);
    return -1;
}

int vhost_load_allowed_methods(const char *m, ec_method_mask_t *pmm)
{
    size_t nelems, i;
    char **tv = NULL;

    dbg_return_if(m == NULL, -1);
    dbg_return_if(pmm == NULL, -1);

    *pmm = EC_METHOD_MASK_UNSET;

    dbg_err_if(u_strtok(m, " \t", &tv, &nelems));

    for (i = 0; i < nelems; ++i)
    {
        if (!strcasecmp(tv[i], "GET"))
            *pmm |= EC_GET_MASK;
        else if (!strcasecmp(tv[i], "POST"))
            *pmm |= EC_POST_MASK;
        else if (!strcasecmp(tv[i], "PUT"))
            *pmm |= EC_PUT_MASK;
        else if (!strcasecmp(tv[i], "DELETE"))
            *pmm |= EC_DELETE_MASK;
        else
            con_err("unknown method %s", tv[i]);
    }

    u_strtok_cleanup(tv, nelems);

    return 0;
err:
    if (tv)
        u_strtok_cleanup(tv, nelems);
    return -1;
}

int vhost_load_resource_attrs(ec_res_t *res, u_config_t *attrs)
{
    int bv;
    const char *v;

    dbg_return_if(res == NULL, -1);
    dbg_return_if(attrs == NULL, -1);

    if ((v = u_config_get_subkey_value(attrs, "if")) != NULL)
    {
        con_err_ifm(ec_res_attrs_set_if(res, v),
                "setting if= attribute to %s", v);
    }

    if ((v = u_config_get_subkey_value(attrs, "rt")) != NULL)
    {
        con_err_ifm(ec_res_attrs_set_rt(res, v),
                "setting rt= attribute to %s", v);
    }

    /* Default for 'exp' is false. */
    con_err_ifm(u_config_get_subkey_value_b(attrs, "exp", false, &bv),
            "bad boolean value");
    con_err_ifm(ec_res_attrs_set_exp(res, (bool) bv),
            "setting exp= attribute to %d", bv);

    /* Default for 'obs' is false. */
    con_err_ifm(u_config_get_subkey_value_b(attrs, "obs", false, &bv),
            "bad boolean value");
    con_err_ifm(ec_res_attrs_set_obs(res, (bool) bv),
            "setting obs= attribute to %d", bv);

    return 0;
err:
    return -1;
}

int server_init(void)
{
    dbg_err_if((g_ctx.base = event_base_new()) == NULL);
    dbg_err_if((g_ctx.dns = evdns_base_new(g_ctx.base, 1)) == NULL);
    dbg_err_if((g_ctx.coap = ec_init(g_ctx.base, g_ctx.dns)) == NULL);
    dbg_err_if((g_ctx.fs = ec_filesys_create(g_ctx.rel_refs)) == NULL);

    if (g_ctx.bsz)
        dbg_err_if(ec_set_block_size(g_ctx.coap, g_ctx.bsz));

    return 0;
err:
    server_term();
    return -1;
}

int server_run(void)
{
    return event_base_dispatch(g_ctx.base);
}

void server_term(void)
{
    if (g_ctx.coap)
    {
        ec_term(g_ctx.coap);
        g_ctx.coap = NULL;
    }

    if (g_ctx.dns)
    {
        evdns_base_free(g_ctx.dns, 0);
        g_ctx.dns = NULL;
    }

    if (g_ctx.base)
    {
        event_base_free(g_ctx.base);
        g_ctx.base = NULL;
    }

    if (g_ctx.fs)
    {
        ec_filesys_destroy(g_ctx.fs);
        g_ctx.fs = NULL;
    }

    return;
}

int server_bind(u_config_t *cfg)
{
    int i;
    u_config_t *addr;
    const char *v;
    char a[256];
    uint16_t port;

    dbg_return_if(cfg == NULL, -1);

    /* Bind all the specified 'addr' records. */
    for (i = 0; (addr = u_config_get_child_n(cfg, "addr", i)) != NULL; ++i)
    {
        if ((v = u_config_get_value(addr)) == NULL)
        {
            u_con("skipping empty 'addr' record...");
            continue;
        }

        con_err_ifm(parse_addr(v, a, sizeof a, &port),
                "error parsing %s", v);

        /* Try to bind the requested address. */
        con_err_ifm(ec_bind_socket(g_ctx.coap, a, port),
                "error binding %s:%u", a, port);
    }

    return 0;
err:
    return -1;
}

int parse_addr(const char *ap, char *a, size_t a_sz, uint16_t *p)
{
    int tmp;
    char *ptr;
    size_t alen;

    dbg_return_if(ap == NULL, -1);
    dbg_return_if(a == NULL, -1);
    dbg_return_if(a_sz == 0, -1);
    dbg_return_if(p == NULL, -1);

    /* Extract port, if specified. */
    if ((ptr = strchr(ap, '+')) != NULL && ptr[1] != '\0')
    {
        con_err_ifm(u_atoi(++ptr, &tmp), "could not parse port %s", ptr);
        *p = (uint16_t) tmp;
    }
    else
    {
        ptr = (char *)(ap + strlen(ap) + 1);
        *p = EC_COAP_DEFAULT_PORT;
    }

    alen = (size_t)(ptr - ap - 1);

    con_err_ifm(alen >= a_sz,
            "not enough bytes (%zu vs %zu) to copy %s", alen, a_sz, ap);

    (void) strncpy(a, ap, alen);
    a[alen] = '\0';

    return 0;
err:
    return -1;
}

void usage(const char *prog)
{
    const char *us =
        "Usage: %s [opts]                                               \n"
        "                                                               \n"
        "   where opts is one of:                                       \n"
        "       -h  this help                                           \n"
        "       -v  be verbose                                          \n"
        "       -f <conf file>      (default is "DEFAULT_CONF")         \n"
        "       -b <block size>     set preferred Block size            \n"
        "       -s <num>            separate response after num seconds \n"
        "       -R                  use relative-ref instead of URI in  \n"
        "                           /.well-known/core entries           \n"
        "                                                               \n"
        ;

    u_con(us, prog);

    exit(EXIT_FAILURE);
    return;
}

/* Payload serving callback. */
const uint8_t *ob_serve(const char *uri, ec_mt_t mt, size_t *p_sz, void *args)
{
    u_unused_args(mt, args);

    CHAT("Producing resource representation for observed URI %s", uri);

    *p_sz = strlen("hello observe");

    return (const uint8_t *) "hello observe";
}

ec_cbrc_t serve(ec_server_t *srv, void *u0, struct timeval *tv, bool resched)
{
    ec_mt_t mta[16];
    size_t mta_sz = sizeof mta / sizeof(ec_mt_t);
    ec_rep_t *rep;
    ec_res_t *res;
    char uri[U_URI_STRMAX];
    bool is_proxy;

    u_unused_args(u0);

    /* Get the requested URI and method. */
    dbg_if (ec_request_get_uri(srv, uri, &is_proxy) == NULL);
    ec_method_t method = ec_server_get_method(srv);

    CHAT("%s %s", ec_method_str(method), uri);

    /* Tell'em to use test/proxy to support Proxy-Uri's. */
    if (is_proxy)
    {
        dbg_if (ec_response_set_code(srv, EC_PROXYING_NOT_SUPPORTED));
        return EC_CBRC_READY;
    }

    /* See if configured for separate responses. */
    if (resched == false && g_ctx.sep.tv_sec)
    {
        *tv = g_ctx.sep;
        u_con("reschedule %s() for %s in %llu seconds",
              __func__, uri, (long long) g_ctx.sep.tv_sec);
        return EC_CBRC_WAIT;
    }

    /* See if it is a query for the /.well-known/core URI. */
    if (!strcasecmp(ec_request_get_uri_path(srv), "/.well-known/core"))
    {
        (void) serve_wkc(srv, method);
        return EC_CBRC_READY;
    }

    /* Get Accept'able media types. */
    con_err_if(ec_request_get_acceptable_media_types(srv, mta, &mta_sz));

    /* Try to retrieve a representation that fits client request. */
    rep = ec_filesys_get_suitable_rep(g_ctx.fs, ec_server_get_url(srv), mta, 
            mta_sz, NULL);

    /* If found, craft the response. */
    if (rep)
    {
        dbg_err_if((res = ec_rep_get_res(rep)) == NULL);

        /* Make sure resource supports the requested method.
         * Bypass check for Proxy-Uri requests because of Publish admin
         * operations (will be checked in PUT/DELETE handlers.) */
        if (!ec_request_via_proxy(srv)
                && ec_resource_check_method(res, method))
        {
            (void) ec_response_set_code(srv, EC_METHOD_NOT_ALLOWED);
            return EC_CBRC_READY;
        }

        switch (method)
        {
            case EC_COAP_GET:
                (void) serve_get(srv, rep);
                return EC_CBRC_READY;

            case EC_COAP_DELETE:
                (void) serve_delete(srv, uri);
                return EC_CBRC_READY;

            case EC_COAP_PUT:
                (void) serve_put(srv, rep);
                return EC_CBRC_READY;

            case EC_COAP_POST:
                (void) serve_post(srv);
                return EC_CBRC_READY;

            default:
                ec_response_set_code(srv, EC_NOT_IMPLEMENTED);
                return EC_CBRC_READY;
        }
    }
    else
        (void) ec_response_set_code(srv, EC_NOT_FOUND);

    return EC_CBRC_READY;
err:
    return EC_CBRC_ERROR;
}

/* Stateless Block2 handling */
static int set_payload(ec_server_t *srv, const uint8_t *data, size_t data_sz)
{
    blockopt_t b2 = { .bnum = 0, .more = false, .bsz = 0 };
    const uint8_t *p;
    size_t p_sz;
    size_t bsz = g_ctx.bsz ? g_ctx.bsz : EC_COAP_BLOCK_MAX;

    /* If Block2 option was received (early negotiation), use its info. */
    if (ec_request_get_block2(srv, &b2.bnum, &b2.more, &b2.bsz) == 0)
        if (b2.bsz)
            bsz = U_MIN(b2.bsz, bsz);

    /* Single block if data fits. */
    if (data_sz <= bsz)
    {
        p = data;
        p_sz = data_sz;
    }
    else  /* Otherwise we have > 1 blocks and add Block2 option. */
    {
        p = data + (b2.bnum * bsz);

        b2.more = (b2.bnum < (data_sz / bsz));

        if (b2.more)
            p_sz = bsz;
        else
            p_sz = data_sz - b2.bnum * bsz;

        dbg_err_if (ec_response_add_block2(srv, b2.bnum, b2.more, bsz));
    }

    (void) ec_response_set_payload(srv, p, p_sz);

    return 0;
err:
    return -1;
}

int serve_wkc(ec_server_t *srv, ec_method_t method)
{
    dbg_return_if(srv == NULL, -1);

    char wkc[EC_WKC_MAX] = { '\0' };

    /* No operation other than GET is allowed on the /.well-known/core. */
    if (method != EC_COAP_GET)
    {
        (void) ec_response_set_code(srv, EC_METHOD_NOT_ALLOWED);
        return 0;
    }

    dbg_err_if(ec_filesys_well_known_core(g_ctx.fs,
            ec_request_get_uri_origin(srv),
            ec_request_get_uri_query(srv), wkc) == NULL);

    (void) set_payload(srv, (uint8_t *) wkc, strlen(wkc));
    (void) ec_response_set_code(srv, EC_CONTENT);
    (void) ec_response_add_content_type(srv, EC_MT_APPLICATION_LINK_FORMAT);

    return 0;
err:
    return -1;
}

int serve_get(ec_server_t *srv, ec_rep_t *rep)
{
    ec_res_t *res = ec_rep_get_res(rep);

    /* Set response code, payload, etag and content-type. */
    (void) set_payload(srv, rep->data, rep->data_sz);
    (void) ec_response_set_code(srv, EC_CONTENT);
    (void) ec_response_add_etag(srv, rep->etag, sizeof rep->etag);
    (void) ec_response_add_content_type(srv, rep->media_type);

    /* Add max-age if != from default. */
    if (res->max_age != EC_COAP_DEFAULT_MAX_AGE)
        (void) ec_response_add_max_age(srv, res->max_age);

    /* See if the client asked for Observing the resource. */
    if (ec_request_get_observe(srv) == 0)
    {
        uint16_t o_cnt;

        /* Add a NON notifier attached to ob_serve callback. */
        if (!ec_add_observer(srv, ob_serve, NULL, res->max_age,
                rep->media_type, EC_COAP_NON, rep->etag,
                sizeof rep->etag))
        {
            /* Get counter from time */
            (void) ec_get_observe_counter(&o_cnt);
            (void) ec_response_add_observe(srv, o_cnt);
        }
        else
            u_dbg("could not add requested observation");
    }

    return 0;
}

/*
 * The DELETE method requests that the resource identified by the
 * request URI be deleted.  A 2.02 (Deleted) response SHOULD be sent on
 * success or in case the resource did not exist before the request.
 * DELETE is not safe, but idempotent.
 */
int serve_delete(ec_server_t *srv, const char *uri)
{
    /* TODO handle conditional deletion of resources. */

    if (ec_filesys_del_resource(g_ctx.fs, uri) == 0)
    {
        (void) ec_response_set_code(srv, EC_DELETED);
        dbg_if(ec_unregister_cb(g_ctx.coap, uri));
    }
    else
        (void) ec_response_set_code(srv, EC_NOT_FOUND);

    return 0;
}

/*
   The PUT method requests that the resource identified by the request
   URI be updated or created with the enclosed representation.  The
   representation format is specified by the media type given in the
   Content-Type Option.

   If a resource exists at the request URI the enclosed representation
   SHOULD be considered a modified version of that resource, and a 2.04
   (Changed) response SHOULD be returned.  If no resource exists then
   the server MAY create a new resource with that URI, resulting in a
   2.01 (Created) response.  If the resource could not be created or
   modified, then an appropriate error response code SHOULD be sent.

   Further restrictions to a PUT can be made by including the If-Match
   (see Section 5.10.9) or If-None-Match (see Section 5.10.10) options
   in the request.

   PUT is not safe, but idempotent.
 */
int serve_put(ec_server_t *srv, ec_rep_t *rep)
{
    /* This routine handles the update of a resource using the PUT method.
     * Creation of a resource via PUT is done by the create() routine. */

    ec_mt_t mta[1];
    size_t pload_sz;
    uint8_t etag[EC_ETAG_SZ] = { 0 }, *pload;
    ec_res_t *res = ec_rep_get_res(rep);
    blockopt_t b1 = { .bnum = 0, .more = false, .bsz = 0 };

    /* Check conditionals:
     * 1) If-None-Match
     * "If the target resource does exist, then the server MUST NOT perform
     *  the requested method.  Instead, the server MUST respond with the 4.12
     *  (Precondition Failed) response code." */
    if (res && ec_request_get_if_none_match(srv) == 0)
    {
        (void) ec_response_set_code(srv, EC_PRECONDITION_FAILED);
        return 0;
    }

    /* 2) If-Match (TODO) */

    /* Get payload and media type (if specified.) */
    pload = ec_request_get_payload(srv, &pload_sz);
    dbg_err_if (ec_request_get_content_type(srv, &mta[1]));

    /* Handle Block1 Option.
     * Implementation is stateful: we just check that bnum corresponds to
     * expected and add the new representation atomically. */
    if (ec_request_get_block1(srv, &b1.bnum, &b1.more, &b1.bsz) == 0)
    {
        dbg_err_if (b1.bnum != g_ctx.b1.bnum++);

        if (g_ctx.bsz)
           b1.bsz = U_MIN(b1.bsz, g_ctx.bsz);

        dbg_err_if (ec_response_add_block1(srv, b1.bnum, b1.more, b1.bsz));
    }

    /* First block. */
    if (g_ctx.resbuf == NULL)
        dbg_err_if (u_buf_create(&g_ctx.resbuf));

    /* All blocks are appended to resource buffer. */
    dbg_err_if (u_buf_append(g_ctx.resbuf, pload, pload_sz));

    /* Last block - now we can process it. */
    if ((pload_sz <= b1.bsz) && !b1.more)
    {
        /* Add new representation. */
        dbg_err_if (ec_resource_add_rep(res, u_buf_ptr(g_ctx.resbuf),
                    u_buf_len(g_ctx.resbuf), mta[1], etag));

        /* Delete old in case media-type matches. */
        if (mta[1] == rep->media_type)
            (void) ec_rep_del(res, rep);

        /* Return Etag of the new representation. */
        (void) ec_response_add_etag(srv, etag, sizeof etag);

        /* Reset state. */
        u_buf_free(g_ctx.resbuf);
        g_ctx.resbuf = NULL;
        g_ctx.b1.bnum = 0;
        g_ctx.b1.more = false;
        g_ctx.b1.bsz = 0;
    }

    (void) ec_response_set_code(srv, EC_CHANGED);

    return 0;
err:
    (void) ec_response_set_code(srv, EC_INTERNAL_SERVER_ERROR);
    return -1;
}

/*
 * The POST method requests that the representation enclosed in the
 * request be processed.  The actual function performed by the POST
 * method is determined by the origin server and dependent on the target
 * resource.  It usually results in a new resource being created or the
 * target resource being updated.
 *
 * If a resource has been created on the server, a 2.01 (Created)
 * response that includes the URI of the new resource in a sequence of
 * one or more Location-Path and/or Location-Query Options SHOULD be
 * returned.  If the POST succeeds but does not result in a new resource
 * being created on the server, a 2.04 (Changed) response SHOULD be
 * returned.  If the POST succeeds and results in the target resource
 * being deleted, a 2.02 (Deleted) response SHOULD be returned.
 *
 * POST is neither safe nor idempotent.
 */
int serve_post(ec_server_t *srv)
{
   (void) ec_response_set_code(srv, EC_CREATED);
    return EC_CBRC_READY;

#if 0
    /* This routine handles the creation of a resource using the POST method. */
    ec_mt_t mt;
    uint8_t *pload;
    size_t pload_sz;
    ec_res_t *res = NULL;
    bool is_proxy = false;
    ec_method_mask_t mm = EC_METHOD_MASK_ALL;
    char uri[U_URI_STRMAX], *first, *uri_tmp, *uri_res;

    /* Get payload (may be empty/NULL).
     * If it is not empty/NULL check/parse the content */
    pload = ec_request_get_payload(srv, &pload_sz);

    first = strtok((char *) pload, ">");
    do
    {
        uri_tmp = strpbrk(first, "<");

        (void) ec_request_get_uri(srv, uri, &is_proxy);

        uri_res = strcat(uri, ++uri_tmp);

        CHAT("adding resource for: %s", uri_res);

        /* Create resource with all methods allowed. */
        dbg_err_ifm ((res = ec_resource_new(uri_res, mm, 3600)) == NULL,
                "resource creation failed");

        /* Get media type (if not specified default to text/plain. */
        if (ec_request_get_content_type(srv, &mt))
            mt = EC_MT_TEXT_PLAIN;

        /* Create new resource representation with the requested media type. */
        /* Each resource only has one representation in this implementation.
         * Use automatic ETag. */
        dbg_err_ifm (ec_resource_add_rep(res, (const uint8_t *) " ", 1, mt, NULL),
                "error adding representation for %s", uri_res);

        /* Attach resource to FS. */
        dbg_err_ifm (ec_filesys_put_resource(g_ctx.fs, res),
                "adding resource failed");
        res = NULL;

        /* Register the callback that will serve this URI.
         * XXX If we get an error here it's really a bad thing because
         * the resource has been already registered and we go into an
         * inconsistent state. */
        dbg_err_ifm (ec_register_cb(g_ctx.coap, uri_res, serve, NULL),
                "registering callback for %s failed", uri_res);

        first = NULL;
        uri[0] = '\0';
        first = strtok(NULL, ">");
    }
    while (first != NULL);

    /* 2.01 Created */
    (void) ec_response_set_code(srv, EC_CREATED);

    return EC_CBRC_READY;
err:
    if (res)
        ec_resource_free(res);
    return EC_CBRC_ERROR;
#endif
}

ec_cbrc_t create(ec_server_t *srv, void *u0, struct timeval *u1, bool u2)
{
    uint8_t *pload;
    size_t pload_sz;
    ec_res_t *res = NULL;
    ec_method_t method;
    bool is_proxy = false;
    char uri[U_URI_STRMAX];
    ec_mt_t mt;
    ec_method_mask_t mm = EC_METHOD_MASK_ALL;

    u_unused_args(u0, u1, u2);

    /* Get the requested URI and method. */
    (void) ec_request_get_uri(srv, uri, &is_proxy);

    switch ((method = ec_server_get_method(srv)))
    {
        case EC_COAP_POST:
            (void) serve_post(srv);
            return EC_CBRC_READY;
        case EC_COAP_PUT:
            break;
        default:
            (void) ec_response_set_code(srv, EC_NOT_FOUND);
            return EC_CBRC_READY;
    }

    CHAT("adding resource for: %s", uri);

    /* Create resource with all methods allowed. */
    con_err_ifm((res = ec_resource_new(uri, mm, 3600)) == NULL,
            "resource creation failed");

    /* Get payload (may be empty/NULL). */
    pload = ec_request_get_payload(srv, &pload_sz);

    /* Get media type (if not specified default to text/plain. */
    if (ec_request_get_content_type(srv, &mt))
        mt = EC_MT_TEXT_PLAIN;

    /* Create new resource representation with the requested media type. */
    /* Each resource only has one representation in this implementation.
     * Use automatic ETag. */
    dbg_err_ifm (ec_resource_add_rep(res, pload, pload_sz, mt, NULL),
            "error adding representation for %s", uri);

    /* Attach resource to FS. */
    dbg_err_ifm (ec_filesys_put_resource(g_ctx.fs, res),
            "adding resource failed");
    res = NULL;

    /* Register the callback that will serve this URI.
     * XXX If we get an error here it's really a bad thing because
     * the resource has been already registered and we go into an
     * inconsistent state. */
    dbg_err_ifm (ec_register_cb(g_ctx.coap, uri, serve, NULL),
            "registering callback for %s failed", uri);

    /* 2.01 Created */
    (void) ec_response_set_code(srv, EC_CREATED);

    return EC_CBRC_READY;
err:
    if (res)
        ec_resource_free(res);
    return EC_CBRC_ERROR;
}


