#include <unistd.h>
#include <getopt.h>
#include <strings.h>
#include <evcoap.h>
#include <u/libu.h>

#include "evcoap_filesys.h"
#include "evcoap_observe.h"

int facility = LOG_LOCAL0;

#define CHAT(...)   do { if (g_ctx.verbose) u_con(__VA_ARGS__); } while (0)
#define DEFAULT_ADDR    "0.0.0.0"
#define DEFAULT_PORT    3865
#define DEFAULT_TOUT    10

typedef struct
{
    ec_t *coap;
    struct event_base *base;
    struct evdns_base *dns;
    ec_filesys_t *cache;
    size_t block_sz;
    bool verbose;
    struct timeval sep;
    struct timeval app_tout;
    char *addr;
    uint16_t port;
} ctx_t;

ctx_t g_ctx =
{
    .coap = NULL,
    .base = NULL,
    .dns = NULL,
    .cache = NULL,
    .block_sz = 0,  /* By default Block is fully under user control. */
    .verbose = false,
    .sep = { .tv_sec = 0, .tv_usec = 0 },
    .app_tout = { .tv_sec = DEFAULT_TOUT, .tv_usec = 0 },
    .addr = DEFAULT_ADDR,
    .port = DEFAULT_PORT
};

int proxy_init(void);
int proxy_run(void);
int proxy_bind(void);
void proxy_term(void);

ec_cbrc_t cache_serve(ec_server_t *srv, void *u0, struct timeval *u1, bool u2);
ec_cbrc_t proxy_req(ec_server_t *s, void *u0, struct timeval *u1, bool u2);
void proxy_res(ec_client_t *cli);
int cache_put(ec_server_t *srv, const char *uri);
int cache_get(ec_server_t *srv, const char *uri, ec_mt_t *mta, size_t mta_sz);
void usage(const char *prog);

int main(int ac, char *av[])
{
    int c;

    while ((c = getopt(ac, av, "b:hRs:v")) != -1)
    {
        switch (c)
        {
            case 'b':
                if (sscanf(optarg, "%zu", &g_ctx.block_sz) != 1)
                    usage(av[0]);
                break;
            case 'v':
                g_ctx.verbose = true;
                break;
            case 's':
                if (sscanf(optarg, "%lld", (long long *)&g_ctx.sep.tv_sec) != 1)
                    usage(av[0]);
                break;
            case 'h':
            default:
                usage(av[0]);
        }
    }

    /* Initialize libevent and evcoap machinery. */
    con_err_ifm(proxy_init(), "evcoap initialization failed");

    /* Bind configured addresses. */
    con_err_ifm(proxy_bind(), "proxy socket setup failed");

    con_err_ifm(ec_register_fb(g_ctx.coap, proxy_req, NULL),
            "error registering proxy_req");

    con_err_ifm(proxy_run(), "proxy run failed");

    return EXIT_SUCCESS;
err:
    proxy_term();

    return EXIT_FAILURE;
}

int proxy_init(void)
{
    dbg_err_if((g_ctx.base = event_base_new()) == NULL);
    dbg_err_if((g_ctx.dns = evdns_base_new(g_ctx.base, 1)) == NULL);
    dbg_err_if((g_ctx.coap = ec_init(g_ctx.base, g_ctx.dns)) == NULL);
    dbg_err_if((g_ctx.cache = ec_filesys_create(false)) == NULL);

    if (g_ctx.block_sz)
        dbg_err_if(ec_set_block_size(g_ctx.coap, g_ctx.block_sz));

    return 0;
err:
    proxy_term();
    return -1;
}

int proxy_run(void)
{
    return event_base_dispatch(g_ctx.base);
}

void proxy_term(void)
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

    if (g_ctx.cache)
    {
        ec_filesys_destroy(g_ctx.cache);
        g_ctx.cache = NULL;
    }

    return;
}

/* TODO default may be overridden by command line. */
int proxy_bind(void)
{
    /* Try to bind the requested address. */
    con_err_ifm(ec_bind_socket(g_ctx.coap, g_ctx.addr, g_ctx.port),
            "error binding %s:%u", g_ctx.addr, g_ctx.port);

    return 0;
err:
    return -1;
}

/* Leave it alone for now. */
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
        "       -b <block size>     enables automatic Block handling    \n"
        "       -s <num>            separate response after num seconds \n"
        "                                                               \n"
        ;

    u_con(us, prog);

    exit(EXIT_FAILURE);
    return;
}

int cache_put(ec_server_t *srv, const char *uri)
{
    ec_mt_t mt[1];
    ec_method_mask_t mm;
    ec_res_t *res;
    ec_rep_t *rep;
    uint8_t *pload, etag[EC_ETAG_SZ] = { 0 };
    size_t pload_sz;
   
    res = ec_filesys_get_resource(g_ctx.cache, uri);

    /* Test If-None-Match */
    if (res && ec_request_get_if_none_match(srv) == 0)
    {
        (void) ec_response_set_code(srv, EC_PRECONDITION_FAILED);
        return 0;
    }

    /* Catch Publish updates. */
    if (ec_request_via_proxy(srv)
            && ec_request_get_publish(srv, &mm) == 0)
    {
        /* Bad allowed-methods mask. */
        if (mm == EC_METHOD_MASK_UNSET) 
        {
            dbg_if (ec_response_set_code(srv, EC_BAD_OPTION));
            return 0;
        }

        /* Get payload and media type (if specified.) */
        pload = ec_request_get_payload(srv, &pload_sz);
        dbg_err_if (ec_request_get_content_type(srv, &mt[0]));

        /* Search for a matching representation before creating the
         * new one. */
        rep = ec_resource_get_suitable_rep(res, mt, 1, NULL);

        /* Add new representation. */
        dbg_err_if (ec_resource_add_rep(res, pload, pload_sz, mt[0], etag));

        /* Delete old in case it exists. */
        if (rep)
            dbg_if (ec_rep_del(res, rep));

        /* Return Etag of the new representation. */
        dbg_if (ec_response_add_etag(srv, etag, sizeof etag));
        dbg_if (ec_response_set_code(srv, EC_CHANGED));

        return 0;
    }

    /* TODO handle PUTs on !Publish'ed resources. */
    dbg_if (ec_response_set_code(srv, EC_NOT_IMPLEMENTED));

    return 0;
err:
    return -1;
}

int cache_get(ec_server_t *srv, const char *uri, ec_mt_t *mta, size_t mta_sz)
{
    ec_rep_t *rep;
    ec_res_t *res;
    
    /* Retrieve resource representation (TODO conditional GET.) */
    rep = ec_filesys_get_suitable_rep(g_ctx.cache, uri, mta, mta_sz, NULL);
    if (rep == NULL)
    {
        dbg_if (ec_response_set_code(srv, EC_NOT_FOUND));
        return 0;
    }

    /* Add payload and Etag. */
    dbg_if (ec_response_set_payload(srv, rep->data, rep->data_sz));
    dbg_if (ec_response_add_etag(srv, rep->etag, sizeof rep->etag));

    /* Add Content-Type if multiple Accept were supplied. */
    if (mta_sz)
        dbg_if (ec_response_add_content_type(srv, rep->media_type));

    res = ec_rep_get_res(rep);

    /* Add Max-Age if different from default. */
    if (res->max_age != EC_COAP_DEFAULT_MAX_AGE)
        dbg_if (ec_response_add_max_age(srv, res->max_age));

    /* 2.05 Content */
    dbg_if (ec_response_set_code(srv, EC_CONTENT));

    /* TODO handle possible Observe. */

    return 0;
}

ec_cbrc_t cache_serve(ec_server_t *srv, void *u0, struct timeval *u1, bool u2)
{
    u_unused_args(u0, u1, u2);

    char uri[U_URI_STRMAX];
    bool is_proxy;
    ec_method_t method;
    ec_mt_t mta[16];
    size_t mta_sz = sizeof mta / sizeof(ec_mt_t);

    /* Retrieve method, URI and Accept'able media types. */
    dbg_err_if ((method = ec_server_get_method(srv)) == EC_METHOD_UNSET);
    dbg_err_if (ec_request_get_uri(srv, uri, &is_proxy));
    dbg_err_if (ec_request_get_acceptable_media_types(srv, mta, &mta_sz));

    switch (method)
    {
        case EC_COAP_GET:
            dbg_err_if (cache_get(srv, uri, mta, mta_sz));
            break;
        case EC_COAP_PUT:
            dbg_err_if (cache_put(srv, uri));
        case EC_COAP_DELETE:
        case EC_COAP_POST:
            ec_response_set_code(srv, EC_NOT_IMPLEMENTED);
            break;
    }

    return EC_CBRC_READY;
err:
    return EC_CBRC_ERROR;
}

ec_cbrc_t proxy_req(ec_server_t *srv, void *u0, struct timeval *u1, bool u2)
{
    u_unused_args(u0, u1, u2);

    ec_client_t *cli = NULL;
    char uri[U_URI_STRMAX];
    bool is_proxy;
    ec_msg_model_t mm = EC_COAP_NON;
    ec_method_mask_t mask;
    ec_res_t *res = NULL;

    /* Get URI of the requested resource. */
    dbg_err_if (ec_request_get_uri(srv, uri, &is_proxy) == NULL);

    /* Expect Proxy-Uri here. */
    if (!is_proxy)
    {
        (void) ec_response_set_code(srv, EC_BAD_REQUEST);
        return EC_CBRC_READY;
    }

    /* Get method (Should be named ec_request_get_method()!). */
    ec_method_t m = ec_server_get_method(srv);
    dbg_err_if (m == EC_METHOD_UNSET);

    /* Catch Publish requests. */
    if (m == EC_COAP_PUT && ec_request_get_publish(srv, &mask) == 0)
    {
        ec_mt_t mt;
        uint32_t max_age;
        const uint8_t *pload;
        size_t pload_sz;

        /* Publication default lifetime is 3600 seconds unless specified
         * otherwise via Max-Age. */
        if (ec_request_get_max_age(srv, &max_age))
            max_age = 3600;

        /* Create new cache resource with allowed methods' mask and max-age. */
        dbg_err_if ((res = ec_resource_new(uri, mask, max_age)) == NULL);

        /* Get payload (may be empty/NULL). */
        pload = ec_request_get_payload(srv, &pload_sz);

        /* Get media type (if unspecified default to text/plain.) */
        if (ec_request_get_content_type(srv, &mt))
            mt = EC_MT_TEXT_PLAIN;

        /* Create new resource representation with the requested media type. */
        /* (use auto Etag) */
        dbg_err_if (ec_resource_add_rep(res, pload, pload_sz, mt, NULL));

        /* Attach resource to FS. */
        dbg_err_if (ec_filesys_put_resource(g_ctx.cache, res));
        res = NULL;

        /* Register the callback that will serve this URI. */
        dbg_err_if (ec_register_cb(g_ctx.coap, uri, cache_serve, NULL));

        /* Return 2.01 Created */
        (void) ec_response_set_code(srv, EC_CREATED);

        return EC_CBRC_READY;        
    }

    /* Create request towards final destination (TODO extract message model.) */
    dbg_err_if ((cli = ec_request_new(g_ctx.coap, m, uri, mm)) == NULL);

    /* TODO map Options */

    dbg_err_if (ec_request_send(cli, proxy_res, srv, &g_ctx.app_tout));

    return EC_CBRC_WAIT;
err:
    if (cli) ec_client_free(cli);
    if (res) ec_resource_free(res);
    return EC_CBRC_ERROR;
}

void proxy_res(ec_client_t *cli)
{
    size_t pl_sz;
    uint8_t *pl;
    ec_rc_t rc;
    ec_server_t *srv = (ec_server_t *) ec_client_get_args(cli);

    ec_cli_state_t s = ec_client_get_state(cli);

    /* Pick a suitable response code depending on the final state
     * of the client FSM. */ 
    switch (s)
    {
        case EC_CLI_STATE_REQ_DONE:
            rc = ec_response_get_code(cli);
            break; 
        case EC_CLI_STATE_APP_TIMEOUT:
            rc = EC_GATEWAY_TIMEOUT;
            break;
        default:
            rc = EC_BAD_GATEWAY;
            break;
    }

    /* TODO map Options. */

    /* Try to get payload. */
    if ((pl = ec_response_get_payload(cli, &pl_sz)) != NULL)
        dbg_err_if (ec_response_set_payload(srv, pl, pl_sz));

    dbg_err_if (ec_response_set_code(srv, rc));

    /* Tell the server that we've collected all the data and we're ready 
     * to fire. */
    dbg_err_if (ec_server_wakeup(srv));
    return;
err:
    u_dbg("TODO explicit deletion of srv and cli contextes ?");
    return;
}
