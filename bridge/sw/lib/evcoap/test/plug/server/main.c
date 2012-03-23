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
    uint32_t block_no;
    bool more;
    size_t block_sz;
} blockopt_t;

typedef struct
{
    ec_t *coap;
    struct event_base *base;
    struct evdns_base *dns;
    const char *uri;
    ec_filesys_t *fs;
    size_t block_sz;
    struct timeval sep;

    /* TODO multiclient - 1 context per client */
    u_buf_t *resbuf;
    blockopt_t block1;

    uint8_t res_obs[32];   /* changing observed resource */

    bool verbose;
} ctx_t;

ctx_t g_ctx = { 
    .coap = NULL,
    .base = NULL,
    .dns = NULL,
    .uri = DEFAULT_URI, 
    .fs = NULL,
    .block_sz = 0,  /* By default Block is fully under user control. */
    .sep = { .tv_sec = 1, .tv_usec = 0 },
    .resbuf = NULL,
    .verbose = false
};

static int parse_addr(const char *as, char *a, size_t a_sz, int *p);
static void usage(const char *prog);

static int server_init(void);
static int server_set_uri(const char *a);
static void server_term(void);
static int server_run(void);

static int add_resource(const char *path, ec_method_mask_t methods, uint32_t ma,
        const char *media_type, const uint8_t *data, size_t data_sz, 
        const char *rt, ec_server_cb_t cb);
static int mod_res(ec_server_t *srv, const char *url, ec_method_mask_t methods,
        uint32_t ma, const char *media_type, const uint8_t *data, size_t data_sz,
        bool create);
static int set_payload(ec_server_t *srv, const uint8_t *data, size_t data_sz);
static int get_rep(ec_server_t *srv, const char *url);

static ec_cbrc_t resource_cb_dft(ec_server_t *srv, void *u0, struct timeval *u1,
        bool u2);
static ec_cbrc_t resource_cb_separate(ec_server_t *srv, void *u0, struct timeval *u1,
        bool u2);
static ec_cbrc_t resource_cb_large_update(ec_server_t *srv, void *u0,
        struct timeval *u1, bool u2);
static ec_cbrc_t resource_cb_large_create(ec_server_t *srv, void *u0,
        struct timeval *u1, bool u2);
static ec_cbrc_t resource_cb_wkc(ec_server_t *srv, void *u0, struct timeval *u1,
        bool u2);

/* Fill buf with char values looping from '0' to '9'. */
static void init_buf(char *s, size_t s_sz)
{
    size_t n;
    char c = '0';

    for (n = 0; n < s_sz; n++,
            c = (c == '9' ? '0' : c + 1))
        s[n] = c;
}

int main(int ac, char *av[])
{
    int c, port;
    char a[U_URI_STRMAX];
    char largebuf[1500];

    /* Initalisations. */
    init_buf(largebuf, sizeof(largebuf));

    while ((c = getopt(ac, av, "u:b:s:hv")) != -1)
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
            case 's':
                if (sscanf(optarg, "%lld", (long long *)&g_ctx.sep.tv_sec) != 1)
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
    dbg_err_ifm (server_init(), "evcoap initialization failed");

    /* Bind configured addresses. */
    dbg_err_ifm (parse_addr(g_ctx.uri, a, sizeof a, &port), 
                "error parsing: '%s'", g_ctx.uri);
    
    CHAT("binding on %s:%d", a, port);

    dbg_err_ifm (ec_bind_socket(g_ctx.coap, a, port),
            "error binding '%s:%u'", a, port);

    /* Add plugtest resources. */
    dbg_err_ifm (
            add_resource("/test", EC_METHOD_MASK_ALL, 0, "text/plain",
                (const uint8_t *) "Hello world!", strlen("Hello world!"),
                "GenTest", &resource_cb_dft) ||

            add_resource("/seg1/seg2/seg3", EC_GET_MASK, 0, "text/plain",
                (const uint8_t *) "Hello world!", strlen("Hello world!"),
                "SegmentTest", &resource_cb_dft) ||

            add_resource("/query", EC_GET_MASK, 0, "text/plain",
                (const uint8_t *) "Hello world!", strlen("Hello world!"),
                "QueryTest", &resource_cb_dft) ||

            add_resource("/large", EC_GET_MASK, 0, "text/plain",
                (const uint8_t *) largebuf, sizeof(largebuf),
                "LargeTest", &resource_cb_dft) ||

            add_resource("/separate", EC_GET_MASK, 0, "text/plain",
                (const uint8_t *) "Hello world!", strlen("Hello world!"),
                "SeparateTest", &resource_cb_separate) ||

            add_resource("/large-update", EC_GET_MASK | EC_PUT_MASK, 0,
                "text/plain", (const uint8_t *) "Hello world!",
                strlen("Hello world!"),
                "LargeTest", &resource_cb_large_update) ||

            add_resource("/large-create", EC_GET_MASK | EC_POST_MASK, 0,
                "text/plain", (const uint8_t *) "Hello world!",
                strlen("Hello world!"),
                "LargeTest", &resource_cb_large_create) ||

            add_resource("/obs", EC_GET_MASK, 1, "text/plain",
                (const uint8_t *) "Hello world!", strlen("Hello world!"),
                "ObserveTest", &resource_cb_dft) ||

            add_resource("/.well-known/core", EC_GET_MASK, 0,
                "application/link-format", (const uint8_t *) "TODO",
                strlen("TODO"),
                "WKCTest", &resource_cb_wkc),

        "failed adding resources");

    dbg_err_ifm (server_run(), "server run failed");

    return EXIT_SUCCESS;
err:
    server_term();

    return EXIT_FAILURE;
}

static int server_set_uri(const char *a)
{
    dbg_return_if (a == NULL, -1);

    g_ctx.uri = a;
    return 0;
}

static int server_init(void)
{
    dbg_err_if ((g_ctx.base = event_base_new()) == NULL);
    dbg_err_if ((g_ctx.dns = evdns_base_new(g_ctx.base, 1)) == NULL);
    dbg_err_if ((g_ctx.coap = ec_init(g_ctx.base, g_ctx.dns)) == NULL);
    dbg_err_if ((g_ctx.fs = ec_filesys_create(true)) == NULL);

    if (g_ctx.block_sz)
        dbg_err_if (ec_set_block_size(g_ctx.coap, g_ctx.block_sz));

    g_ctx.block1.block_no = 0;
    g_ctx.block1.more = 0;
    g_ctx.block1.block_sz = 0;

    return 0;
err:
    server_term();
    return -1;
}

static int server_run(void)
{
    return event_base_dispatch(g_ctx.base);
}

static void server_term(void)
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

static int parse_addr(const char *as, char *a, size_t a_sz, int *p)
{
    u_uri_t *u = NULL;
    const char *scheme, *port;

    dbg_err_ifm (u_uri_crumble(as, 0, &u), "%s parse error", as);

    /* Check that scheme is 'coap' or 'coaps'. */
    dbg_err_ifm ((scheme = u_uri_get_scheme(u)) == NULL ||
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

static void usage(const char *prog)
{
    const char *us =
        "Usage: %s [opts]                                               \n"
        "                                                               \n"
        "   where opts is one of:                                       \n"
        "       -h  this help                                           \n"
        "       -v  be verbose                                          \n"
        "       -u <uri>            (default is "DEFAULT_URI")          \n"
        "       -b <block size>     (enables automatic Block handling)  \n"
        "       -s <num>            separate response after num seconds \n"
        "                                                               \n"
        ;

    u_con(us, prog);

    exit(EXIT_FAILURE);
    return;
}

static int add_resource(const char *path, ec_method_mask_t methods, uint32_t ma,
        const char *media_type, const uint8_t *data, size_t data_sz, 
        const char *rt, ec_server_cb_t cb)
{
    char uri[U_URI_STRMAX];
    ec_res_t *res = NULL;
    ec_mt_t mt;

    CHAT("adding resource for: %s", path);

    /* Create complete resource name. */
    dbg_err_ifm (u_snprintf(uri, sizeof uri, "%s%s", g_ctx.uri, path),
            "could not create uri for path %s and origin %s", path, g_ctx.uri);

    /* Create resource. */
    dbg_err_ifm ((res = ec_resource_new(uri, methods, ma)) == NULL,
            "resource creation failed");

    /* If Resource Type is defined, use it. */
    if (rt)
        dbg_err_if (ec_res_attrs_set_rt(res, rt));

    /* Convert representation type. */
    dbg_err_ifm (ec_mt_from_string(media_type, &mt), "media type map error");

    /* Each resource only has one representation in this implementation. */
    dbg_err_ifm (ec_resource_add_rep(res, data, data_sz, mt, NULL),
                "error adding representation for %s", uri);

    /* Attach resource to FS. */
    dbg_err_ifm (ec_filesys_put_resource(g_ctx.fs, res),
            "adding resource failed");

    /* Register the callback that will serve this URI. */
    dbg_err_ifm (ec_register_cb(g_ctx.coap, uri, cb, NULL),
            "registering callback for %s failed", path);
            
    return 0;
err:
    if (res)
        ec_resource_free(res);

    return -1;
}

/* Payload serving callback. */
static const uint8_t *ob_serve(const char *uri, ec_mt_t mt, size_t *p_sz, void *args)
{
    static int i=0;
    u_unused_args(mt, args);

    CHAT("Producing resource representation for observed URI %s", uri);

    /* Simple changing resource. */
    dbg_err_if (u_snprintf((char *) g_ctx.res_obs, sizeof(g_ctx.res_obs),
                "hello observe: %d", i++));
    *p_sz = strlen((char *) g_ctx.res_obs);

    return g_ctx.res_obs;
err:
    return NULL;
}

/* Helper to get a suitable representation of resource. */
static int get_rep(ec_server_t *srv, const char *url)
{
    ec_rep_t *rep;
    ec_res_t *res;
    ec_mt_t mta[16];
    size_t mta_sz = sizeof mta / sizeof(ec_mt_t);

    /* Get Accept'able media types. */
    dbg_err_if (ec_request_get_acceptable_media_types(srv, mta, &mta_sz));

    /* Try to retrieve a representation that fits client request. */
    rep = ec_filesys_get_suitable_rep(g_ctx.fs, url, mta, mta_sz, NULL);
    if (rep == NULL) {
        (void) ec_response_set_code(srv, EC_NOT_FOUND);
        return 0;
    }

    /* Get parent resource. */
    res = ec_rep_get_res(rep);
    dbg_err_if (res == NULL);

    /* Set payload (or Block if necessary). */
    dbg_err_if (set_payload(srv, rep->data, rep->data_sz));
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
err:    
    return -1;
}


/* Helper to modify a resource. TODO per-client session */
static int mod_res(ec_server_t *srv, const char *url, ec_method_mask_t methods,
        uint32_t ma, const char *media_type, const uint8_t *data, size_t data_sz,
        bool create)
{
    ec_res_t *res;
    ec_mt_t mt;
    uint32_t bnum;
    bool more;
    size_t block_sz;

    dbg_err_if (srv == NULL);
    dbg_err_if (url == NULL);
    dbg_err_if (methods == 0);
    dbg_err_if (media_type == NULL);
    dbg_err_if (data == NULL);
    dbg_err_if (data_sz == 0);

    if (ec_request_get_block1(srv, &bnum, &more, &block_sz) == 0 && more) {

        dbg_err_if (bnum != g_ctx.block1.block_no++);

        if (g_ctx.block_sz)
           block_sz = U_MIN(block_sz, g_ctx.block_sz);

        dbg_err_if (ec_response_add_block1(srv, bnum, more, block_sz));
    }

    if (g_ctx.resbuf == NULL) 
        dbg_err_if (u_buf_create(&g_ctx.resbuf));

    dbg_err_if (u_buf_append(g_ctx.resbuf, data, data_sz));

    if (data_sz < block_sz)    /* final packet */
    {
        dbg_err_ifm (ec_mt_from_string(media_type, &mt), "media type map error");

        if (!create) /* it's an update */
            dbg_err_if (ec_filesys_del_resource(g_ctx.fs, url));

        /* Create resource. */
        dbg_err_ifm ((res = ec_resource_new(url, methods, ma)) == NULL,
            "resource creation failed");

        /* TODO only change rep!!! */
        /* Each resource only has one representation in this implementation. */
        dbg_err_ifm (ec_resource_add_rep(res, u_buf_ptr(g_ctx.resbuf),
                    u_buf_len(g_ctx.resbuf), mt, NULL), 
                "error adding representation for %s", url);

        /* Attach resource to FS. */
        dbg_err_ifm (ec_filesys_put_resource(g_ctx.fs, res),
                "adding resource failed");

        u_buf_free(g_ctx.resbuf);
        g_ctx.resbuf = NULL;

        /* Reinitialise Block1 values. */
        g_ctx.block1.block_no = 0;
        g_ctx.block1.more = 0;
        g_ctx.block1.block_sz = 0;
    }

    (void) ec_response_set_code(srv, EC_CHANGED);

    return 0;
err:
    if (g_ctx.resbuf)
        u_buf_free(g_ctx.resbuf);

    return -1;
}

static int set_payload(ec_server_t *srv, const uint8_t *data, size_t data_sz)
{
    uint32_t bnum = 0;
    bool more;
    size_t bsz;
    const uint8_t *p;
    size_t p_sz;
    size_t block_sz = g_ctx.block_sz ? g_ctx.block_sz : EC_COAP_BLOCK_MAX;

    /* If Block2 option was received, use its info. */
    if (ec_request_get_block2(srv, &bnum, &more, &bsz) == 0)
        if (bsz)
            block_sz = U_MIN(bsz, block_sz);

    /* Single block if data fits. */
    if (data_sz <= block_sz)
    {
        p = data;
        p_sz = data_sz;
    }
    else  /* Otherwise we have > 1 blocks and add Block2 option. */
    {
        p = data + (bnum * block_sz);

        more = (bnum < (data_sz / block_sz));

        if (more)
            p_sz = block_sz;
        else
            p_sz = data_sz - bnum * block_sz;

        dbg_err_if (ec_response_add_block2(srv, bnum, more, block_sz));
    }

    (void) ec_response_set_payload(srv, p, p_sz);

    return 0;
err:
    return -1;
}

static ec_cbrc_t resource_cb_dft(ec_server_t *srv, void *u0,
        struct timeval *u1, bool u2)
{
    const char *url;
    ec_method_t method;
    uint8_t *payload;
    size_t payload_sz;

    dbg_err_if (srv == NULL);

    u_unused_args(u0, u1, u2);

    CHAT("[%s]", __func__);

    url = ec_server_get_url(srv);
    method = ec_server_get_method(srv);
    payload = ec_request_get_payload(srv, &payload_sz);

    switch (method)
    {
        case EC_COAP_GET:
            //XXX WRONG???
            dbg_err_if (get_rep(srv, url));
            break;

        case EC_COAP_POST:
            dbg_err_if (get_rep(srv, url));
            (void) ec_response_set_code(srv, EC_CREATED);  /* fake */
            break;

        case EC_COAP_PUT:
            dbg_err_if (get_rep(srv, url));
            (void) ec_response_set_code(srv, EC_CHANGED);  /* fake */
            break;

        case EC_COAP_DELETE:
            dbg_err_if (get_rep(srv, url));
            (void) ec_response_set_code(srv, EC_DELETED);  /* fake */
            break;

        default:
            dbg_err("unsupported method: %d", method);
    }

    return EC_CBRC_READY;
err:
    return EC_CBRC_ERROR;
}

static ec_cbrc_t resource_cb_separate(ec_server_t *srv, void *u0, 
        struct timeval *u1, bool u2)
{
    bool resched = u2;
    struct timeval *tv = u1;

    CHAT("[%s]", __func__);

    if (resched)
        return resource_cb_dft(srv, u0, u1, u2);

    /* !resched: sleep for the configured amount of time */
    u_dbg("delaying for %d secs", g_ctx.sep.tv_sec);

    tv->tv_sec = g_ctx.sep.tv_sec;
    tv->tv_usec = 0;

    return EC_CBRC_WAIT;
}

static ec_cbrc_t resource_cb_large_update(ec_server_t *srv, void *u0, 
        struct timeval *u1, bool u2)
{
    const char *url;
    ec_method_t method;
    uint8_t *payload;
    size_t payload_sz;

    dbg_err_if (srv == NULL);

    u_unused_args(u0, u1, u2);

    CHAT("[%s]", __func__);

    url = ec_server_get_url(srv);
    method = ec_server_get_method(srv);
    payload = ec_request_get_payload(srv, &payload_sz);

    switch (method)
    {
        case EC_COAP_GET:
            dbg_err_if (get_rep(srv, url));
            break;

        case EC_COAP_PUT:
            dbg_err_if (mod_res(srv, url, EC_GET_MASK | EC_PUT_MASK, 0,
                        "text/plain", payload, payload_sz, false));
            break;
        
        default:
            (void) ec_response_set_code(srv, EC_METHOD_NOT_ALLOWED);
            goto err;
    }

    return EC_CBRC_READY;
err:
    return EC_CBRC_ERROR;
}

static ec_cbrc_t resource_cb_large_create(ec_server_t *srv, void *u0, 
        struct timeval *u1, bool u2)
{
    const char *url;
    ec_method_t method;
    uint8_t *payload;
    size_t payload_sz;

    dbg_err_if (srv == NULL);

    u_unused_args(u0, u1, u2);

    CHAT("[%s]", __func__);

    url = ec_server_get_url(srv);
    method = ec_server_get_method(srv);
    payload = ec_request_get_payload(srv, &payload_sz);

    switch (method)
    {
        case EC_COAP_GET:
            dbg_err_if (get_rep(srv, url));
            break;

        case EC_COAP_POST:
            dbg_err_if (mod_res(srv, url, EC_GET_MASK | EC_PUT_MASK, 0,
                        "text/plain", payload, payload_sz, true));
            (void) ec_response_set_code(srv, EC_CREATED);
            break;
        
        default:
            (void) ec_response_set_code(srv, EC_METHOD_NOT_ALLOWED);
            goto err;
    }

    return EC_CBRC_READY;
err:
    return EC_CBRC_ERROR;
}

static ec_cbrc_t resource_cb_wkc(ec_server_t *srv, void *u0, 
        struct timeval *u1, bool u2)
{
    ec_method_t method;
    char wkc[EC_WKC_MAX] = { '\0' };

    u_unused_args(srv, u0, u1, u2);

    CHAT("[%s]", __func__);

    method = ec_server_get_method(srv);

    /* No operation other than GET is allowed on the /.well-known/core. */
    if (method != EC_COAP_GET)
    {
        (void) ec_response_set_code(srv, EC_METHOD_NOT_ALLOWED);
        return 0;
    }

    dbg_err_if(ec_filesys_well_known_core(g_ctx.fs,
            ec_request_get_uri_origin(srv),
            ec_request_get_uri_query(srv), wkc) == NULL);

    (void) ec_response_set_code(srv, EC_CONTENT);
    (void) ec_response_set_payload(srv, (uint8_t *) wkc, strlen(wkc));
    (void) ec_response_add_content_type(srv, EC_MT_APPLICATION_LINK_FORMAT);

    return EC_CBRC_READY;
err:
    return EC_CBRC_ERROR;
}
