#include <unistd.h>
#include <getopt.h>
#include <strings.h>
#include <evcoap.h>
#include <u/libu.h>

#include "evcoap_filesys.h"
#include "evcoap_observe.h"

int facility = LOG_LOCAL0;

#define CHAT(...) \
    do { if (g_ctx.verbose) u_con(__VA_ARGS__); } while (0)

#define DEFAULT_URI "coap://[::1]:"EC_COAP_DEFAULT_SPORT

typedef enum
{
    METHOD_NONE     = 0,
    METHOD_GET      = (1 << 0),
    METHOD_PUT      = (1 << 1),
    METHOD_POST     = (1 << 2),
    METHOD_DELETE   = (1 << 3),
    METHOD_ALL      = (METHOD_GET | METHOD_PUT | METHOD_POST | METHOD_DELETE)
} method_t;

typedef struct
{
    ec_t *coap;
    struct event_base *base;
    struct evdns_base *dns;
    const char *uri;
    ec_filesys_t *fs;
    size_t block_sz;
    bool verbose;
} ctx_t;

ctx_t g_ctx = { 
    .coap = NULL,
    .base = NULL,
    .dns = NULL,
    .uri = DEFAULT_URI, 
    .fs = NULL,
    .block_sz = 0,  /* By default Block is fully under user control. */
    .verbose = false
};

int parse_addr(const char *as, char *a, size_t a_sz, int *p);
void usage(const char *prog);

int server_init(void);
int server_set_uri(const char *a);
void server_term(void);
int server_run(void);

int resource_add(const char *path, method_t method, uint32_t ma, 
        ec_server_cb_t cb, void *arg);
ec_cbrc_t resource_cb_test(ec_server_t *srv, void *u0, struct timeval *u1,
        bool u2);
ec_cbrc_t resource_cb_seg(ec_server_t *srv, void *u0, struct timeval *u1,
        bool u2);
ec_cbrc_t resource_cb_query(ec_server_t *srv, void *u0, struct timeval *u1,
        bool u2);
ec_cbrc_t resource_cb_large(ec_server_t *srv, void *u0, struct timeval *u1,
        bool u2);
ec_cbrc_t resource_cb_large_update(ec_server_t *srv, void *u0,
        struct timeval *u1, bool u2);
ec_cbrc_t resource_cb_large_create(ec_server_t *srv, void *u0,
        struct timeval *u1, bool u2);
ec_cbrc_t resource_cb_obs(ec_server_t *srv, void *u0, struct timeval *u1,
        bool u2);
ec_cbrc_t resource_cb_wellknown(ec_server_t *srv, void *u0, struct timeval *u1,
        bool u2);

int main(int ac, char *av[])
{
    int c, port;
    char a[U_URI_STRMAX];

    while ((c = getopt(ac, av, "u:b:hv")) != -1)
    {
        switch (c)
        {
            case 'u':
                if (server_set_uri(optarg))
                    usage(av[0]);
                break;
            case 'b':
                if (sscanf(optarg, "%zu", &g_ctx.block_sz) != 1)
                    usage(av[0]);
                break;
            case 'v':
                g_ctx.verbose = true;
                break;
            case 'h':
            default: 
                usage(av[0]);
        }
    }

    /* Initialize libevent and evcoap machinery. */
    con_err_ifm (server_init(), "evcoap initialization failed");

    /* Bind configured addresses. */
    con_err_ifm (parse_addr(g_ctx.uri, a, sizeof a, &port), 
                "error parsing: '%s'", g_ctx.uri);
    
    CHAT("binding on %s:%d", a, port);

    con_err_ifm (ec_bind_socket(g_ctx.coap, a, port),
            "error binding '%s:%u'", a, port);

    /* Add plugtest resources. */
    con_err_ifm (
            resource_add("/test", METHOD_ALL, 0, &resource_cb_test, NULL) ||

            resource_add("/seg1/seg2/seg3", METHOD_GET, 0, &resource_cb_seg,
                NULL) ||

            resource_add("/query", METHOD_GET, 0, &resource_cb_query, NULL) ||

            resource_add("/large", METHOD_GET, 0, &resource_cb_large, NULL) ||

            resource_add("/large_update", METHOD_PUT, 0,
                &resource_cb_large_update, NULL) ||

            resource_add("/large_create", METHOD_POST, 0,
                &resource_cb_large_create, NULL) ||

            resource_add("/obs", METHOD_GET, 0, &resource_cb_obs, NULL) ||

            resource_add("/.well-known/core", METHOD_GET, 0,
                &resource_cb_wellknown, NULL
                ), 
        "failed adding resources");
    
    con_err_ifm (server_run(), "server run failed");

    return EXIT_SUCCESS;
err:
    server_term();

    return EXIT_FAILURE;
}

int server_set_uri(const char *a)
{
    dbg_return_if (a == NULL, -1);

    g_ctx.uri = a;
    return 0;
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

int parse_addr(const char *as, char *a, size_t a_sz, int *p)
{
    u_uri_t *u = NULL;
    const char *scheme, *port;

    con_err_ifm (u_uri_crumble(as, 0, &u), "%s parse error", as);

    /* Check that scheme is 'coap' or 'coaps'. */
    con_err_ifm ((scheme = u_uri_get_scheme(u)) == NULL ||
            (strcasecmp(scheme, "coap") && strcasecmp(scheme, "coaps")),
            "bad %s scheme", scheme);

    if ((port = u_uri_get_port(u)) == NULL || *port == '\0')
        dbg_err_if (u_atoi(EC_COAP_DEFAULT_SPORT, p));
    else
        dbg_err_if (u_atoi(port, p));

    dbg_err_if (u_strlcpy(a, "[", a_sz));
    dbg_err_if (u_strlcat(a, u_uri_get_host(u), a_sz));
    dbg_err_if (u_strlcat(a, "]", a_sz));

    u_uri_free(u), u = NULL;
    return 0;
err:
    if (u)
        u_uri_free(u);
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
        "       -u <uri>            (default is "DEFAULT_URI")          \n"
        "       -b <block size>     (enables automatic Block handling)  \n"
        "                                                               \n"
        ;

    u_con(us, prog);

    exit(EXIT_FAILURE);
    return;
}

int resource_add(const char *path, method_t method, uint32_t ma, 
        ec_server_cb_t cb, void *arg)
{
    char uri[U_URI_STRMAX];
    ec_res_t *res = NULL;

    u_unused_args(method);  /* TODO */

    CHAT("adding resource for: %s", path);

    /* Create complete resource name. */
    con_err_ifm (u_snprintf(uri, sizeof uri, "%s%s", g_ctx.uri, path),
            "could not create uri for path %s and origin %s", path, g_ctx.uri);

    /* Create resource. */
    con_err_ifm ((res = ec_resource_new(uri, ma)) == NULL,
            "resource creation failed");

    /* Attach resource to FS. */
    con_err_ifm (ec_filesys_put_resource(g_ctx.fs, res),
            "adding resource failed");

    /* Register the callback that will serve this URI. */
    con_err_ifm (ec_register_cb(g_ctx.coap, uri, cb, arg),
            "registering callback for %s failed", path);
            
    return 0;
err:
    if (res)
        ec_resource_free(res);

    return -1;
}

ec_cbrc_t resource_cb_test(ec_server_t *srv, void *u0, struct timeval *u1, 
        bool u2)
{
    char *s = "Hello World!";

    u_unused_args(srv, u0, u1, u2);

    CHAT("[%s]", __FUNCTION__);

    (void) ec_response_set_code(srv, EC_CONTENT);
    (void) ec_response_set_payload(srv, s, strlen(s));

    return EC_CBRC_READY;
}

ec_cbrc_t resource_cb_seg(ec_server_t *srv, void *u0, struct timeval *u1, 
        bool u2)
{
    u_unused_args(srv, u0, u1, u2);

    CHAT("[%s]", __FUNCTION__);
    
    return EC_CBRC_READY;
}

ec_cbrc_t resource_cb_query(ec_server_t *srv, void *u0, struct timeval *u1, 
        bool u2)
{
    u_unused_args(srv, u0, u1, u2);

    CHAT("[%s]", __FUNCTION__);

    return EC_CBRC_READY;
}

ec_cbrc_t resource_cb_large(ec_server_t *srv, void *u0, struct timeval *u1, 
        bool u2)
{
    u_unused_args(srv, u0, u1, u2);

    CHAT("[%s]", __FUNCTION__);

    return EC_CBRC_READY;
}

ec_cbrc_t resource_cb_large_update(ec_server_t *srv, void *u0, struct timeval *u1, 
        bool u2)
{
    u_unused_args(srv, u0, u1, u2);

    CHAT("[%s]", __FUNCTION__);

    return EC_CBRC_READY;
}

ec_cbrc_t resource_cb_large_create(ec_server_t *srv, void *u0, struct timeval *u1, 
        bool u2)
{
    u_unused_args(srv, u0, u1, u2);

    CHAT("[%s]", __FUNCTION__);

    return EC_CBRC_READY;
}

ec_cbrc_t resource_cb_obs(ec_server_t *srv, void *u0, struct timeval *u1, 
        bool u2)
{
    u_unused_args(srv, u0, u1, u2);

    CHAT("[%s]", __FUNCTION__);

    return EC_CBRC_READY;
}

ec_cbrc_t resource_cb_wellknown(ec_server_t *srv, void *u0, struct timeval *u1, 
        bool u2)
{
    u_unused_args(srv, u0, u1, u2);

    CHAT("[%s]", __FUNCTION__);

    return EC_CBRC_READY;
}
