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

int resource_add(const char *path, ec_method_mask_t methods, uint32_t ma, 
        const char *media_type, const uint8_t *data, size_t data_sz, 
        ec_server_cb_t cb);
ec_cbrc_t resource_cb_dft(ec_server_t *srv, void *u0, struct timeval *u1,
        bool u2);
ec_cbrc_t resource_cb_separate(ec_server_t *srv, void *u0, struct timeval *u1,
        bool u2);
#if 0
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
#endif

/* Fill a string with char values looping from 'a' to 'z'. */
static void init_str(char *s, size_t s_sz)
{
    size_t n;
    char c = 'a';

    for (n = 0; n < s_sz; n++,
            c = (c == 'z' ? 'a' : 'b'))
        s[n] = c;

    s[s_sz-1] = '\0';
}

int main(int ac, char *av[])
{
    int c, port;
    char a[U_URI_STRMAX];
    char longstr[EC_COAP_BLOCK_MAX * 3];

    /* Initalisations. */
    init_str(longstr, sizeof(longstr));

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
            resource_add("/test", EC_METHOD_MASK_ALL, 0, "text/plain", 
                (const uint8_t *) "Hello world!", strlen("Hello world!"),
                &resource_cb_dft) ||

            resource_add("/seg1/seg2/seg3", EC_GET_MASK, 0, "text/plain",
                (const uint8_t *) "Hello world!", strlen("Hello world!"),
                &resource_cb_dft) ||

            resource_add("/query", EC_GET_MASK, 0, "text/plain",
                (const uint8_t *) "Hello world!", strlen("Hello world!"),
                &resource_cb_dft) ||

            resource_add("/large", EC_GET_MASK, 0, "text/plain",
                (const uint8_t *) longstr, strlen(longstr),
                &resource_cb_dft) ||

            resource_add("/separate", EC_GET_MASK, 0, "text/plain",
                (const uint8_t *) "Hello world!", strlen("Hello world!"),
                &resource_cb_separate) ||

            resource_add("/large_update", EC_PUT_MASK, 0, "text/plain",
                (const uint8_t *) "Hello world!", strlen("Hello world!"),
                &resource_cb_dft) ||

            resource_add("/large_create", EC_POST_MASK, 0, "text/plain",
                (const uint8_t *) "Hello world!", strlen("Hello world!"),
                &resource_cb_dft) ||

            resource_add("/obs", EC_GET_MASK, 0, "text/plain", 
                (const uint8_t *) "Hello world!", strlen("Hello world!"),
                &resource_cb_dft) ||

            resource_add("/.well-known/core", EC_GET_MASK, 0,
                "application/link-format", (const uint8_t *) "TODO",
                strlen("TODO"), &resource_cb_dft),

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

int resource_add(const char *path, ec_method_mask_t methods, uint32_t ma, 
        const char *media_type, const uint8_t *data, size_t data_sz, 
        ec_server_cb_t cb)
{
    char uri[U_URI_STRMAX];
    ec_res_t *res = NULL;
    ec_mt_t mt;

    CHAT("adding resource for: %s", path);

    /* Create complete resource name. */
    con_err_ifm (u_snprintf(uri, sizeof uri, "%s%s", g_ctx.uri, path),
            "could not create uri for path %s and origin %s", path, g_ctx.uri);

    /* Create resource. */
    con_err_ifm ((res = ec_resource_new(uri, methods, ma)) == NULL,
            "resource creation failed");

    /* Convert representation type. */
    con_err_ifm (ec_mt_from_string(media_type, &mt), "media type map error");

    /* Each resource only has one representation in this implementation. */
    con_err_ifm (ec_resource_add_rep(res, data, data_sz, mt, NULL),
                "error adding representation for %s", uri);

    /* Attach resource to FS. */
    con_err_ifm (ec_filesys_put_resource(g_ctx.fs, res),
            "adding resource failed");

    /* Register the callback that will serve this URI. */
    con_err_ifm (ec_register_cb(g_ctx.coap, uri, cb, NULL),
            "registering callback for %s failed", path);
            
    return 0;
err:
    if (res)
        ec_resource_free(res);

    return -1;
}

ec_cbrc_t resource_cb_dft(ec_server_t *srv, void *u0, struct timeval *u1, 
        bool u2)
{
    ec_mt_t mta[16];
    size_t mta_sz = sizeof mta / sizeof(ec_mt_t);
    ec_rep_t *rep;
    ec_res_t *res;
    const char *url;
    ec_method_t method;
    uint8_t *payload;
    size_t payload_sz;

    con_err_if (srv == NULL);

    u_unused_args(u0, u1, u2);

    CHAT("[%s]", __FUNCTION__);

    url = ec_server_get_url(srv);
    method = ec_server_get_method(srv);

    /* Get Accept'able media types. */
    con_err_if (ec_request_get_acceptable_media_types(srv, mta, &mta_sz));

    /* Try to retrieve a representation that fits client request. */
    rep = ec_filesys_get_suitable_rep(g_ctx.fs, url, mta, mta_sz, NULL);
    if (rep == NULL) {
        (void) ec_response_set_code(srv, EC_NOT_FOUND);
        goto end;
    }

    /* Get parent resource. */
    res = ec_rep_get_res(rep);
    dbg_err_if (res == NULL);

    /* Make sure resource supports requested method. */
    if (ec_resource_check_method(res, method))
    {
        (void) ec_response_set_code(srv, EC_METHOD_NOT_ALLOWED);
        goto end;
    }

    /* Always return current representation. */
    (void) ec_response_set_payload(srv, rep->data, rep->data_sz);
    (void) ec_response_add_content_type(srv, rep->media_type);

    /* Add max-age if != from default. */
    if (res->max_age != EC_COAP_DEFAULT_MAX_AGE)
        (void) ec_response_add_max_age(srv, res->max_age);

    /* Display payload if available. */
    payload = ec_request_get_payload(srv, &payload_sz);
    if (payload)
        u_info("payload: %*s", payload_sz, payload);

    switch (method)
    {
        case EC_COAP_GET:
            (void) ec_response_set_code(srv, EC_CONTENT);
            break;

        case EC_COAP_POST:
            (void) ec_response_set_code(srv, EC_CREATED);  /* fake */
            break;

        case EC_COAP_PUT:
            (void) ec_response_set_code(srv, EC_CHANGED);  /* fake */
            break;

        case EC_COAP_DELETE:
            (void) ec_response_set_code(srv, EC_DELETED);  /* fake */
            break;

        default:
            con_err("unsupported method: %d", method);
    }

end:
    return EC_CBRC_READY;
err:
    return EC_CBRC_ERROR;
}

ec_cbrc_t resource_cb_separate(ec_server_t *srv, void *u0, struct timeval *u1,
        bool u2)
{
    bool resched = u2;
    struct timeval *tv = u1;

    CHAT("[%s]", __FUNCTION__);

    if (resched)
        return resource_cb_dft(srv, u0, u1, u2);

    /* !resched: just a sec! */
    tv->tv_sec = 1;

    return EC_CBRC_WAIT;
}

#if 0
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
#endif
