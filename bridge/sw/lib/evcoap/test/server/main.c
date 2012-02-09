#include <unistd.h>
#include <getopt.h>
#include <strings.h>
#include <evcoap.h>
#include <u/libu.h>

#include "evcoap_filesys.h"

int facility = LOG_LOCAL0;

#define CHAT(...)   do { if (g_ctx.verbose) u_con(__VA_ARGS__); } while (0)
#define DEFAULT_CONF    "./coap-server.conf"

typedef struct
{
    ec_t *coap;
    struct event_base *base;
    struct evdns_base *dns;
    const char *conf;
    ec_filesys_t *fs;
    size_t block_sz;
    bool verbose;
} ctx_t;

ctx_t g_ctx = { 
    .coap = NULL,
    .base = NULL,
    .dns = NULL,
    .conf = DEFAULT_CONF, 
    .fs = NULL,
    .block_sz = 0,  /* By default Block is fully under user control. */
    .verbose = false
};

int server_init(void);
void server_term(void);
int server_run(void);
int server_bind(u_config_t *cfg);

int vhost_setup(u_config_t *vhost);
int vhost_load_contents(u_config_t *vhost, const char *origin);
int vhost_load_resource(u_config_t *res, const char *origin);

int parse_addr(const char *ap, char *a, size_t a_sz, uint16_t *p);
int normalize_origin(const char *o, char co[U_URI_STRMAX]);

ec_cbrc_t serve(ec_server_t *srv, void *u0, struct timeval *u1, bool u2);

void usage(const char *prog);


int main(int ac, char *av[])
{
    int c, i;
    u_config_t *cfg = NULL, *vhost;

    while ((c = getopt(ac, av, "b:hf:v")) != -1)
    {
        switch (c)
        {
            case 'b':
                if (sscanf(optarg, "%zu", &g_ctx.block_sz) != 1)
                    usage(av[0]);
                break;
            case 'f':
                g_ctx.conf = optarg;
                break;
            case 'v':
                g_ctx.verbose = true;
                break;
            case 'h':
            default: 
                usage(av[0]);
        }
    }

    /* Load configuration from file. */
    con_err_ifm (u_config_load_from_file(g_ctx.conf, &cfg),
            "error loading %s", g_ctx.conf);

    /* Initialize libevent and evcoap machinery. */
    con_err_ifm (server_init(), "evcoap initialization failed");

    /* Bind configured addresses. */
    con_err_ifm (server_bind(cfg), "server socket setup failed");

    /* Setup configured virtual hosts. */
    for (i = 0; (vhost = u_config_get_child_n(cfg, "vhost", i)) != NULL; ++i)
        con_err_ifm (vhost_setup(vhost), "configuration error");
    con_err_ifm (i == 0, "no origins configured");
    
    con_err_ifm (server_run(), "server run failed");

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

    dbg_return_if (vhost == NULL, -1);

    /* For each origin specified for this vhost... */
    for (i = 0;
            (origin = u_config_get_child_n(vhost, "origin", i)) != NULL;
            ++i)
    {
        /* Get and check origin. */
        con_err_ifm ((o = u_config_get_value(origin)) == NULL,
                "missing origin value !");

        con_err_ifm (normalize_origin(o, co), "origin check failed");

        /* Load contents. */
        con_err_ifm (vhost_load_contents(vhost, co), "could not load contents");
    }

    return 0;
err:
    return -1;
}

int normalize_origin(const char *o, char co[U_URI_STRMAX])
{
    u_uri_t *u = NULL;
    const char *scheme, *port;

    dbg_return_if (o == NULL || o[0] == '\0', -1);
    dbg_return_if (co == NULL, -1);

    con_err_ifm (u_uri_crumble(o, 0, &u), "%s parse error", o);

    /* Check that scheme is 'coap' or 'coaps'. */
    con_err_ifm ((scheme = u_uri_get_scheme(u)) == NULL ||
            (strcasecmp(scheme, "coap") && strcasecmp(scheme, "coaps")),
            "bad %s scheme", scheme);

    /* Set default port if empty. */
    if ((port = u_uri_get_port(u)) == NULL || *port == '\0')
        (void) u_uri_set_port(u, EC_COAP_DEFAULT_SPORT);

    con_err_ifm (u_uri_knead(u, co), "error normalizing origin (%s)", o);

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
    u_config_t *res, *contents;

    dbg_return_if (vhost == NULL, -1);
    dbg_return_if (origin == NULL, -1);

    /* Pick up the "contents" section. */
    con_err_ifm (u_config_get_subkey(vhost, "contents", &contents),
            "no contents in virtual host !");

    /* Load hosted resources. */
    for (i = 0;
            (res = u_config_get_child_n(contents, "resource", i)) != NULL;
            ++i)
    {
        con_err_ifm (vhost_load_resource(res, origin),
                "error loading resource");
    }

    con_err_ifm (i == 0, "no resources in virtual host");

    return 0;
err:
    return -1;
}

int vhost_load_resource(u_config_t *resource, const char *origin)
{
    int tmp;
    size_t i, val_sz;
    uint32_t ma;
    const char *path, *max_age, *val;
    ec_filesys_res_t *res = NULL;
    ec_mt_t mt;
    char uri[512];
    u_config_t *repr;

    dbg_return_if (resource == NULL, -1);

    /* Get resource path. */
    con_err_ifm ((path = u_config_get_subkey_value(resource, "path")) == NULL,
            "missing mandatory \'path\' in resource");

    /* Get resource max age (default to 60 secs if not specified.) */
    if ((max_age = u_config_get_subkey_value(resource, "max-age")) == NULL)
        ma = 60;
    else
    {
        con_err_ifm (u_atoi(max_age, &tmp), "conversion error for %s", max_age);
        ma = (uint32_t) tmp;
    }

    /* Create complete resource name. */
    con_err_ifm (u_snprintf(uri, sizeof uri, "%s%s", origin, path),
            "could not create uri for path %s and origin %s", path, origin);

    CHAT("adding resource %s", uri);

    /* Create FS resource. */
    con_err_ifm ((res = ec_filesys_new_resource(uri, ma)) == NULL,
            "resource creation failed");

    /* Load each resource representation. */
    for (i = 0; (repr = u_config_get_child_n(resource, 
                    "representation", i)) != NULL; ++i)
    {
        /* Retrieve representation type and value. */
        con_err_ifm (ec_mt_from_string(u_config_get_subkey_value(repr, "t:"),
                    &mt), "media type map error");

        con_err_ifm ((val = u_config_get_subkey_value(repr, "v:")) == NULL, 
                "no value for resource %s", uri);
        val_sz = strlen(val);

        con_err_ifm (ec_filesys_add_rep(res, (const uint8_t *) val, 
                    val_sz, mt, NULL),
                "error adding representation for %s", uri);
    }
    con_err_ifm (i == 0, "no resources in virtual host");

    /* Put resource into the file system. */
    con_err_ifm (ec_filesys_put_resource(g_ctx.fs, res), 
            "adding resource failed");
    res = NULL; /* ownership lost */

    /* Register the callback that will serve this URI. */
    con_err_ifm (ec_register_cb(g_ctx.coap, uri, serve, NULL),
            "registering callback for %s failed", uri);

    return 0;
err:
    if (res)
        ec_filesys_free_resource(res);
    return -1;
}

int server_init(void)
{
    dbg_err_if ((g_ctx.base = event_base_new()) == NULL);
    dbg_err_if ((g_ctx.dns = evdns_base_new(g_ctx.base, 1)) == NULL);
    dbg_err_if ((g_ctx.coap = ec_init(g_ctx.base, g_ctx.dns)) == NULL);
    dbg_err_if ((g_ctx.fs = ec_filesys_create()) == NULL);

    if (g_ctx.block_sz)
        dbg_err_if (ec_set_block_size(g_ctx.coap, g_ctx.block_sz));

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

    dbg_return_if (cfg == NULL, -1);

    /* Bind all the specified 'addr' records. */
    for (i = 0; (addr = u_config_get_child_n(cfg, "addr", i)) != NULL; ++i)
    {
        if ((v = u_config_get_value(addr)) == NULL)
        {
            u_con("skipping empty 'addr' record...");
            continue; 
        }

        con_err_ifm (parse_addr(v, a, sizeof a, &port), 
                "error parsing %s", v);

        /* Try to bind the requested address. */
        con_err_ifm (ec_bind_socket(g_ctx.coap, a, port),
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

    dbg_return_if (ap == NULL, -1);
    dbg_return_if (a == NULL, -1);
    dbg_return_if (a_sz == 0, -1);
    dbg_return_if (p == NULL, -1);

    /* Extract port, if specified. */
    if ((ptr = strchr(ap, '+')) != NULL && ptr[1] != '\0')
    {
        con_err_ifm (u_atoi(++ptr, &tmp), "could not parse port %s", ptr);
        *p = (uint16_t) tmp;
    }
    else
    {
        ptr = (char *) (ap + strlen(ap) + 1);
        *p = EC_COAP_DEFAULT_PORT;
    }

    alen = (size_t) (ptr - ap - 1);

    con_err_ifm (alen >= a_sz, 
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
        "       -b <block size>     (enables automatic Block handling)  \n"
        "                                                               \n"
        ;

    u_con(us, prog);

    exit(EXIT_FAILURE);
    return;
}

ec_cbrc_t serve(ec_server_t *srv, void *u0, struct timeval *u1, bool u2)
{
    ec_mt_t mta[16];
    size_t mta_sz = sizeof mta / sizeof(ec_mt_t);
    ec_filesys_rep_t *rep;
    const char *url;

    u_unused_args(u0, u1, u2);

    /* Get the requested URI and method (GET only at present.) */
    con_err_ifm (!(url = ec_server_get_url(srv)), "no URL (!)");

    if (ec_server_get_method(srv) != EC_GET)
    {
        (void) ec_response_set_code(srv, EC_NOT_IMPLEMENTED); 
        goto end;
    }

    CHAT("requested resource is '%s'", url);
    
    /* Get Accept'able media types. */
    con_err_if (ec_request_get_acceptable_media_types(srv, mta, &mta_sz));

    /* Try to retrieve a representation that fits client request. */
    rep = ec_filesys_get_suitable_rep(g_ctx.fs, url, mta, mta_sz, NULL);

    if (rep)
    {
        /* Set response code, payload, etag and content-type. */
        (void) ec_response_set_code(srv, EC_CONTENT);
        (void) ec_response_set_payload(srv, rep->data, rep->data_sz);
        (void) ec_response_add_etag(srv, rep->etag, sizeof rep->etag);
        (void) ec_response_add_content_type(srv, rep->media_type);
    }
    else
        (void) ec_response_set_code(srv, EC_NOT_FOUND);

end:
    return EC_CBRC_READY;
err:
    return EC_CBRC_ERROR;
}

