#define _GNU_SOURCE
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <u/libu.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/event_compat.h>
#include <evcoap.h>

#define CHAT(...)   do { if (g_ctx.verbose) u_con(__VA_ARGS__); } while (0)

int facility = LOG_LOCAL0;

#define DEFAULT_URI     "coap://[::1]/.well-known/core"
#define DEFAULT_OFN     "./response.payload"
#define DEFAULT_TOUT    60
#define DEFAULT_BLOCK   128

typedef struct
{
    uint32_t block_no;
    bool more;
    size_t block_sz;
} blockopt_t;

typedef struct 
{
    ec_t *coap;
    ec_client_t *cli;
    struct event_base *base;
    struct evdns_base *dns;
    struct event *evsig;
    const char *uri;
    ec_method_t method;
    ec_msg_model_t model;
    struct timeval app_tout;
    uint8_t etag[4];
    const char *ofn;
    const char *pfn;
    uint32_t retry;
    uint32_t observe;
    bool verbose;
    bool fail;
    bool token;
    size_t block_sz;
    uint8_t *data;
    size_t data_sz;
    blockopt_t b1;
    blockopt_t b2;
    size_t iblock;      /* index of current block */
    ec_mt_t mt;
    bool publish;
    ec_method_mask_t allowed_methods;
    bool use_proxy;
    char proxy_host[256];
    uint16_t proxy_port;
} ctx_t;

ctx_t g_ctx = {
    .coap = NULL,
    .cli = NULL,
    .base = NULL,
    .dns = NULL,
    .evsig = NULL,
    .uri = DEFAULT_URI,
    .method = EC_COAP_GET,
    .model = EC_COAP_NON,
    .app_tout = { .tv_sec = DEFAULT_TOUT, .tv_usec = 0 },
    .etag = { 0xde, 0xad, 0xbe, 0xef },
    .ofn = DEFAULT_OFN,
    .pfn = NULL,
    .retry = 0,
    .observe = 0,
    .verbose = false,
    .fail = false,
    .token = false,
    .data = NULL,
    .data_sz = 0,
    .block_sz = 0,      /* block size defined by user */
    .b1 = { .block_no = 0, .more = 0, .block_sz = 0 },
    .b2 = { .block_no = 0, .more = 0, .block_sz = 0 },
    .iblock = 0,
    .mt = EC_MT_ANY,
    .publish = false,
    .use_proxy = false,
};

void usage(const char *prog);
int client_init(void);
int client_run(void);
void client_term(void);
int client_set_uri(const char *s);
int client_set_method(const char *s);
int client_set_model(const char *s);
int client_set_observe(const char *s);
int client_set_output_file(const char *s);
int client_set_payload_file(const char *s);
int client_set_retry(const char *s);
int client_set_app_timeout(const char *s);
int client_set_publish_mask(const char *s);
int client_set_proxy(const char *s);
int client_save_to_file(const uint8_t *pl, size_t pl_sz);
int client_set_media_type(const char *s);
int set_payload(ec_client_t *cli, const uint8_t *data, size_t data_sz);
void response_cb(ec_client_t *cli);
void sighup_cb(evutil_socket_t fd, short event, void *arg);

/* TODO Same as in test/server: move to share/ */
int parse_addr(const char *ap, char *a, size_t a_sz, uint16_t *p);

int main(int ac, char *av[])
{
    int c;
    int retry_secs = 1;

    while ((c = getopt(ac, av, "c:hu:m:M:O:o:p:r:x:vt:B:P:T")) != -1)
    {
        switch (c)
        {
            case 'c':
                if (client_set_media_type(optarg))
                    usage(av[0]);
                break;
            case 'u': /* .uri */
                if (client_set_uri(optarg))
                    usage(av[0]);
                break;
            case 'm': /* .method */
                if (client_set_method(optarg))
                    usage(av[0]);
                break;
            case 'M': /* .model */
                if (client_set_model(optarg))
                    usage(av[0]);
                break;
            case 'O':
                if (client_set_observe(optarg))
                    usage(av[0]);
                break;
            case 'o':
                if (client_set_output_file(optarg))
                    usage(av[0]);
                break;
            case 'p':
                if (client_set_payload_file(optarg))
                    usage(av[0]);
                break;
            case 'r':
                if (client_set_retry(optarg))
                    usage(av[0]);
                break;
            case 'v':
                g_ctx.verbose = true;
                break;
            case 't':
                if (client_set_app_timeout(optarg))
                    usage(av[0]);
                break;
            case 'T':
                g_ctx.token = true;
                break;
            case 'B':
                con_err_if (u_atol(optarg, (long *) &g_ctx.block_sz));
                break;
            case 'P':
                if (client_set_publish_mask(optarg))
                    usage(av[0]);
                break;
            case 'x':
                if (client_set_proxy(optarg))
                    usage(av[0]);
                break;
            case 'h':
            default:
                usage(av[0]);
        }
    }

    /* Set up the client transaction. */
    con_err_if (client_init());

retry:
    /* Run, and keep on doing it until all blocks are exhausted. */
    do
    {
        (void) client_run();
    }
    while ((g_ctx.b1.more || g_ctx.b2.more) && !g_ctx.fail);

    if (g_ctx.fail && g_ctx.retry)
    {
        u_dbg("client failed! retrying in %d seconds (%d more)", 
                retry_secs, g_ctx.retry);
        sleep(retry_secs);
        retry_secs <<= 1;  /* 2^n backoff */
        g_ctx.retry--;
        goto retry;
    }

    client_term();
    return EXIT_SUCCESS;
err:
    client_term();
    return EXIT_FAILURE;
}

void sighup_cb(evutil_socket_t fd, short event, void *arg)
{
    u_unused_args(fd, event, arg);

    /* Simulate reboot by cancelling any running observations. */
    (void) ec_client_cancel_observation(g_ctx.cli);
}

void response_cb(ec_client_t *cli)
{
    ec_rc_t rc;
    ec_cli_state_t s;
    uint8_t *pl;
    size_t pl_sz;
    uint32_t bnum, max_age;
    bool more;
   
    /* 
     * Get FSM final state, bail out on !REQ_DONE (or observe).
     */
    switch ((s = ec_client_get_state(cli)))
    {
        case EC_CLI_STATE_REQ_DONE:
        case EC_CLI_STATE_WAIT_NFY:
            break;
        default:
            con_err("request failed: %s", ec_cli_state_str(s));
    }

    /* 
     * Get response code.
     */
    u_con("%s", ec_rc_str((rc = ec_response_get_code(cli))));
    con_err_ifm (!EC_IS_OK(rc), "request failed");

	/* Always check content for OK codes */

    /* Get response payload. */
    dbg_ifm ((pl = ec_response_get_payload(cli, &pl_sz)) == NULL,
			"empty payload");

    /* Save payload to file. */
    con_err_sifm (pl && client_save_to_file(pl, pl_sz),
            "payload could not be saved");

    /* If it's a reponse to fragmented request (Block1) we set g_ctx.b1. */
    if ((ec_response_get_block1(cli, &bnum, &more,
                &g_ctx.b1.block_sz) == 0))
    {
        /* Blockwise transfer - make sure requested block was returned. */
        dbg_err_if (bnum != g_ctx.b1.block_no);

        g_ctx.b1.block_no++;
    }

    /* If reponse was fragmented (Block2) we set g_ctx.b2. */
    if ((ec_response_get_block2(cli, &bnum, &g_ctx.b2.more,
                &g_ctx.b2.block_sz) == 0) && g_ctx.b2.more)
    {
        /* Blockwise transfer - make sure requested block was returned. */
        dbg_err_if (bnum != g_ctx.b2.block_no);

        g_ctx.b2.block_no = bnum;
    }

    /* In case we've requested an observation on the resource, see if we've
     * been added to the notification list. */
    if (g_ctx.observe && ec_client_is_observing(cli))
    {
        if (ec_response_get_max_age(cli, &max_age) == 0)
            CHAT("notifications expected every %u second(s)", max_age);

        if (--g_ctx.observe == 0)
        {
            (void) ec_client_cancel_observation(cli);
            goto end;
        }

        /* Return here, without breaking the event loop since we
         * need to be called back again on next notification. */
        return;
    }

end:
    ec_loopbreak(ec_client_get_base(cli));
    return;
err:
    g_ctx.fail = true;
    ec_loopbreak(ec_client_get_base(cli));
    return;
}

void usage(const char *prog)
{
    const char *us = 
        "Usage: %s [opts]                                                   \n"
        "                                                                   \n"
        "   where opts is one of:                                           \n"
        "       -h this help                                                \n"
        "       -m <GET|POST|PUT|DELETE>         (default is GET)           \n"
        "       -M <CON|NON>                     (default is NON)           \n"
        "       -o <file>                        (default is "DEFAULT_OFN") \n"
        "       -p <file>                        (default is NULL)          \n"
        "       -r <n_retries>                   (default is no retry)      \n"
        "          how many times to retry upon failure                     \n"
        "       -u <uri>                         (default is "DEFAULT_URI") \n"
        "       -t <timeout>                     (default is %u sec)        \n"
        "       -T generate Token option         (default is no Token)      \n"
        "       -B <block_sz>                    (default is no Block2 -    \n"
        "          generate Block2 option        late negotiation only)     \n"
        "       -O <number of notifications> try to observe the resource    \n"
        "       -c <media-type>                  (default is any)           \n"
        "       -P <all|none|GET|PUT|POST|DELETE>                           \n"
        "       -x <addr[+port]>                 proxy address and opt port \n"
        "                                                                   \n"
        ;

    u_con(us, prog, DEFAULT_TOUT);

    exit(EXIT_FAILURE);
}

int client_init(void)
{
    dbg_err_if ((g_ctx.base = event_base_new()) == NULL);
    dbg_err_if ((g_ctx.dns = evdns_base_new(g_ctx.base, 1)) == NULL);
    dbg_err_if ((g_ctx.coap = ec_init(g_ctx.base, g_ctx.dns)) == NULL);

    /* Set up signals */
    g_ctx.evsig = evsignal_new(g_ctx.base, SIGHUP, sighup_cb, NULL);
    dbg_err_if (g_ctx.evsig == NULL);

    dbg_err_if (event_add(g_ctx.evsig, NULL));

    /* Client instance is possibly reused N times (e.g. Block handling), so we
     * choose to handle deallocation manually via userown == true. */
    g_ctx.cli = !g_ctx.use_proxy
        ? ec_request_new(g_ctx.coap, g_ctx.method, g_ctx.uri, g_ctx.model, true)
        : ec_proxy_request_new(g_ctx.coap, g_ctx.method, g_ctx.uri, g_ctx.model,
                g_ctx.proxy_host, g_ctx.proxy_port, true);
    dbg_err_if (g_ctx.cli == NULL);

    return 0;
err:
    client_term();
    return -1;
}

void client_term(void)
{
    if (g_ctx.cli)
    {
        ec_client_free(g_ctx.cli);
        g_ctx.cli = NULL;
    }

    if (g_ctx.evsig)
    {
        event_free(g_ctx.evsig);
        g_ctx.evsig = NULL;
    }

    if (g_ctx.coap)
    {
        ec_term(g_ctx.coap);
        g_ctx.coap = NULL;
    }

    return;
}

int client_run(void)
{
    /* Client run initialisations. */
    g_ctx.fail = false;

    /* Clear and set all options at each run because request API doesn't easily
     * support deltas (only Block2 Option values change). */
    ec_opts_clear(&g_ctx.cli->req.opts);
    ec_client_add_uri_opts(g_ctx.cli, g_ctx.uri);

    if (g_ctx.publish)
        dbg_err_if (ec_request_add_publish(g_ctx.cli, g_ctx.allowed_methods));

	if (g_ctx.token)
        dbg_err_if (ec_request_add_token(g_ctx.cli, NULL, 0));

    if (g_ctx.observe)
        dbg_err_if (ec_request_add_observe(g_ctx.cli));

    if (g_ctx.method == EC_COAP_GET)
    {
        /* First run - initiate early negotiation. */
        if (g_ctx.block_sz && (g_ctx.iblock++ == 0))
        {
            dbg_err_if (ec_request_add_block2(g_ctx.cli, 0, 0,
                        g_ctx.block_sz));
        }
        else if (g_ctx.b2.more)
        /* More data available - get next block. */
        {
            g_ctx.b2.block_no++;

            g_ctx.b2.block_sz = g_ctx.block_sz
                ? U_MIN(g_ctx.block_sz, g_ctx.b2.block_sz)
                : g_ctx.b2.block_sz;

            CHAT("requesting block n.%u (size: %u)", g_ctx.b2.block_no,
                    g_ctx.b2.block_sz);

            /* The client MUST set the M bit of a Block2 Option to zero. */
            dbg_err_if (ec_request_add_block2(g_ctx.cli, g_ctx.b2.block_no,
                        0, g_ctx.b2.block_sz));
        }

        if (g_ctx.mt != EC_MT_ANY)
            dbg_err_if (ec_request_add_accept(g_ctx.cli, g_ctx.mt));
    }
    
    /* In case of POST/PUT load payload from file (if not NULL). */
    if ((g_ctx.method == EC_COAP_POST || g_ctx.method == EC_COAP_PUT) &&
            g_ctx.pfn)
    {
        if (g_ctx.b1.block_no == 0)
            dbg_err_if (u_load_file(g_ctx.pfn, 0, (char **) &g_ctx.data, 
                        &g_ctx.data_sz));

        /* Set payload (or Block if necessary). */
        dbg_err_if (set_payload(g_ctx.cli, g_ctx.data, g_ctx.data_sz));

        /* Add Content-Type option (default to text/plain.) */
        dbg_err_if (ec_request_add_content_type(g_ctx.cli,
                    g_ctx.mt == EC_MT_ANY ? EC_MT_TEXT_PLAIN : g_ctx.mt));
    }

    CHAT("sending request to %s", g_ctx.uri);
    u_dbg("sending request to %s (base: %p, dns: %p, coap: %p cli: %p)",
            g_ctx.uri, g_ctx.base, g_ctx.dns, g_ctx.coap, g_ctx.cli);
    dbg_err_if (ec_request_send(g_ctx.cli, response_cb, NULL, &g_ctx.app_tout));
    
    return event_base_dispatch(g_ctx.base);
err:
    g_ctx.fail = true;
    return -1;
}

int client_set_uri(const char *s)
{
    dbg_return_if (s == NULL, -1);
    g_ctx.uri = s;
    return 0;
}

int client_set_method(const char *s)
{
    int i;
    struct {
        ec_method_t m;
        const char *s;  
    } methmap[4] = {
        { EC_COAP_GET, "get" }, 
        { EC_COAP_POST, "post" }, 
        { EC_COAP_PUT, "put" }, 
        { EC_COAP_DELETE, "delete" }
    };

    dbg_return_if (s == NULL, -1);

    for (i = 0; i < 4; i++)
    {
        if (!strcasecmp(s, methmap[i].s))
        {
            g_ctx.method = methmap[i].m;
            return 0;
        }
    }

    u_con("unknown method %s", s);
    return -1;
}

int client_set_observe(const char *s)
{
    int tmp;

    dbg_return_if (s == NULL, -1);

    con_return_ifm (u_atoi(s, &tmp) || tmp <= 0, -1,
            "bad observe notification counter '%s'", s);

    g_ctx.observe = (uint32_t) tmp;

    return 0;
}

int client_set_model(const char *s)
{
    dbg_return_if (s == NULL, -1);

    if (!strcasecmp(s, "non"))
    {
        g_ctx.model = EC_COAP_NON; 
        return 0;
    }
    else if (!strcasecmp(s, "con"))
    {
        g_ctx.model = EC_COAP_CON; 
        return 0;
    }

    return -1;
}

int client_set_media_type(const char *s)
{
    con_err_ifm (ec_mt_from_string(s, &g_ctx.mt), "unknown media type: %s", s);

    return 0;
err:
    return -1;
}

int client_set_app_timeout(const char *s)
{
    int tmp;

    dbg_return_if (s == NULL, -1);

    con_err_ifm (u_atoi(s, &tmp), "bad application timeout '%s'", s);

    g_ctx.app_tout.tv_sec = tmp;
    g_ctx.app_tout.tv_usec = 0;

    return 0;
err:
    return -1;
}

int client_set_output_file(const char *s)
{
    dbg_return_if (s == NULL, -1);
    
    g_ctx.ofn = s;

    return 0;
}

int client_set_proxy(const char *s)
{
    con_return_ifm (parse_addr(s, g_ctx.proxy_host, sizeof g_ctx.proxy_host,
                &g_ctx.proxy_port), -1, "bad proxy address %s", s);

    g_ctx.use_proxy = true;

    return 0;
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

int client_set_publish_mask(const char *s)
{
    dbg_return_if (s == NULL, -1);

    if (strcasestr(s, "get"))
        g_ctx.allowed_methods |= EC_GET_MASK;

    if (strcasestr(s, "put"))
        g_ctx.allowed_methods |= EC_PUT_MASK;

    if (strcasestr(s, "post"))
        g_ctx.allowed_methods |= EC_POST_MASK;

    if (strcasestr(s, "delete"))
        g_ctx.allowed_methods |= EC_DELETE_MASK;

    if (strcasestr(s, "all"))
        g_ctx.allowed_methods = EC_METHOD_MASK_ALL;

    if (strcasestr(s, "none"))
        g_ctx.allowed_methods = EC_METHOD_MASK_UNSET;

    g_ctx.publish = true;

    return 0;
}

int client_set_payload_file(const char *s)
{
    dbg_return_if (s == NULL, -1);
    
    g_ctx.pfn = s;

    return 0;
}

int client_set_retry(const char *s)
{
    dbg_return_if (s == NULL, -1);
    
    con_return_ifm (u_atol(s, (long *) &g_ctx.retry),
            -1, "bad number of retries '%s'", s);

    return 0;
}

int client_save_to_file(const uint8_t *pl, size_t pl_sz)
{
    FILE *fp = NULL;

    if (g_ctx.ofn[0] == '-')
    {
        con_err_sifm (fwrite(pl, pl_sz, 1, stdout) != 1,
                "could not write to %s", g_ctx.ofn);
        fflush(stdout);
        return 0;
    }

    fp = fopen(g_ctx.ofn, "w");
    con_err_sifm (fp == NULL, "could not open %s", g_ctx.ofn);

    con_err_sifm (fwrite(pl, pl_sz, 1, fp) != 1, 
            "could not write to %s", g_ctx.ofn);

    (void) fclose(fp);

    return 0;
err:
    if (fp != NULL)
        (void) fclose(fp);
    return -1;
}

int set_payload(ec_client_t *cli, const uint8_t *data, size_t data_sz)
{
    uint32_t bnum = g_ctx.b1.block_no;
    bool more = false;
    const uint8_t *p;
    size_t p_sz;
    size_t block_sz = g_ctx.block_sz ? g_ctx.block_sz : DEFAULT_BLOCK;

    /* Single block if data fits. */
    if (data_sz <= block_sz)
    {
        p = data;
        p_sz = data_sz;
    }
    else  /* Otherwise we have > 1 blocks and add Block1 option. */
    {
        p = data + (bnum * block_sz);

        more = (bnum < (data_sz / block_sz));

        if (more)
            p_sz = block_sz;
        else
            p_sz = data_sz - bnum * block_sz;

        dbg_err_if (ec_request_add_block1(cli, bnum, more, block_sz));
    }

    (void) ec_request_set_payload(cli, p, p_sz);

    g_ctx.b1.more = more;

    return 0;
err:
    return -1;
}
