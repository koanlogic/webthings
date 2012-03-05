#include <unistd.h>
#include <getopt.h>
#include <strings.h>
#include <evcoap.h>
#include <u/libu.h>

#define CHAT(...)   do { if (g_ctx.verbose) u_con(__VA_ARGS__); } while (0)

int facility = LOG_LOCAL0;

#define DEFAULT_URI "coap://[::1]/.well-known/core"
#define DEFAULT_OFN "./response.payload"
#define DEFAULT_TOUT 60

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
    const char *uri;
    ec_method_t method;
    ec_msg_model_t model;
    struct timeval app_tout;
    uint8_t etag[4];
    const char *ofn;
    const char *pfn;
    bool observe;
    bool verbose;
    blockopt_t bopt;
    bool fail;
} ctx_t;

ctx_t g_ctx = {
    .coap = NULL,
    .cli = NULL,
    .base = NULL,
    .dns = NULL,
    .uri = DEFAULT_URI,
    .method = EC_GET,
    .model = EC_NON,
    .app_tout = { .tv_sec = DEFAULT_TOUT, .tv_usec = 0 },
    .etag = { 0xde, 0xad, 0xbe, 0xef },
    .ofn = DEFAULT_OFN,
    .pfn = NULL,
    .observe = false,
    .verbose = false,
    .fail = false
};

void usage(const char *prog);
int client_init(void);
int client_run(void);
void client_term(void);
int client_set_uri(const char *s);
int client_set_method(const char *s);
int client_set_model(const char *s);
int client_set_output_file(const char *s);
int client_set_payload_file(const char *s);
int client_set_app_timeout(const char *s);
int client_save_to_file(const uint8_t *pl, size_t pl_sz);
void cb(ec_client_t *cli);

int main(int ac, char *av[])
{
    int c;

    while ((c = getopt(ac, av, "hu:m:M:Oo:p:vt:")) != -1)
    {
        switch (c)
        {
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
                g_ctx.observe = true;
                break;
            case 'o':
                if (client_set_output_file(optarg))
                    usage(av[0]);
                break;
            case 'p':
                if (client_set_payload_file(optarg))
                    usage(av[0]);
                break;
            case 'v':
                g_ctx.verbose = true;
                break;
            case 't':
                if (client_set_app_timeout(optarg))
                    usage(av[0]);
                break;
            case 'h':
            default:
                usage(av[0]);
        }
    }

    /* Set up the client transaction. */
    con_err_if (client_init());

    /* Run, and keep on doing it until all blocks are exhausted. */
    do { con_err_if (client_run()); } while (g_ctx.bopt.more && !g_ctx.fail);

    con_err_if (g_ctx.fail);

    client_term();
    return EXIT_SUCCESS;
err:
    client_term();
    return EXIT_FAILURE;
}

void cb(ec_client_t *cli)
{
    ec_rc_t rc;
    ec_cli_state_t s;
   
    /* Get FSM final state, bail out on !REQ_DONE. */
    con_err_ifm ((s = ec_client_get_state(cli)) != EC_CLI_STATE_REQ_DONE, 
            "request failed: %s", ec_cli_state_str(s));

    /* Get response code. */
    con_err_ifm ((rc = ec_response_get_code(cli)) == EC_RC_UNSET,
           "could not get response code");

    /* TODO replace with coap_hdr_pretty_print() or similar. */
    u_con("%s", ec_rc_str(rc));

    con_err_if (!EC_IS_OK(rc));

    if (rc == EC_CONTENT)
    {
        uint8_t *pl;
        uint16_t o_serial;
        uint32_t bnum, max_age;
        size_t pl_sz;

        /* Get response payload. */
        con_err_ifm ((pl = ec_response_get_payload(cli, &pl_sz)) == NULL,
                    "empty payload");

        /* If fragmented will set g_ctx.bopt. */
        if ((ec_response_get_block2(cli, &bnum, &g_ctx.bopt.more,
                    &g_ctx.bopt.block_sz) == 0) && g_ctx.bopt.more)
        {
            /* Blockwise transfer - make sure requested block was returned. */
            dbg_err_if (bnum != g_ctx.bopt.block_no);

            g_ctx.bopt.block_no = bnum;
        }

        /* Save payload to file. */
        con_err_sifm (client_save_to_file(pl, pl_sz),
                "payload could not be saved");

        /* See if we've been added to the notification list for the
         * requested resource. */
        if (g_ctx.observe)
        {
            if (ec_response_get_observe(cli, &o_serial) == 0)
            {
                dbg_err_if (ec_response_get_max_age(cli, &max_age));
                CHAT("waiting next notification in %u seconds", max_age);

                /* Return here, without breaking the event loop since we
                 * need to be called back again on next notification. */
                return;
            }
            
            CHAT("Observation could not be established");
        }
    }

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
        "Usage: %s [opts]                                                  \n"
        "                                                                  \n"
        "   where opts is one of:                                          \n"
        "       -h  this help                                              \n"
        "       -m <GET|POST|PUT|DELETE>    (default is GET)               \n"
        "       -M <CON|NON>                (default is NON)               \n"
        "       -O                          observe the requested resource \n"
        "       -o <file>                   (default is "DEFAULT_OFN")     \n"
        "       -p <file>                   (default is NULL)              \n"
        "       -u <uri>                    (default is "DEFAULT_URI")     \n"
        "       -t <timeout>                (default is %u sec)            \n"
        "                                                                  \n"
        ;

    u_con(us, prog, DEFAULT_TOUT);

    exit(EXIT_FAILURE);
}

int client_init(void)
{
    dbg_err_if ((g_ctx.base = event_base_new()) == NULL);
    dbg_err_if ((g_ctx.dns = evdns_base_new(g_ctx.base, 1)) == NULL);
    dbg_err_if ((g_ctx.coap = ec_init(g_ctx.base, g_ctx.dns)) == NULL);

    /* Other local initialisations. */
    g_ctx.bopt.block_no = 0;
    g_ctx.bopt.more = 0;
    g_ctx.bopt.block_sz = 0;

    return 0;
err:
    client_term();
    return -1;
}

void client_term(void)
{
    if (g_ctx.coap)
        ec_term(g_ctx.coap);

    return;
}

int client_run(void)
{
    uint8_t *payload = NULL;
    size_t payload_sz;

    /* Initialisations */
    g_ctx.fail = false;

    dbg_err_if ((g_ctx.cli = ec_request_new(g_ctx.coap, g_ctx.method, 
                    g_ctx.uri, g_ctx.model)) == NULL);

    if (g_ctx.observe)
        dbg_err_if (ec_request_add_observe(g_ctx.cli));

    /* Handle blockwise transfer. */
    if (g_ctx.bopt.more)
    {
        g_ctx.bopt.block_no++;

        CHAT("requesting block n.%u (size: %u)", g_ctx.bopt.block_no,
                g_ctx.bopt.block_sz);

        /* The client MUST set the M bit of a Block2 Option to zero. */
        dbg_err_if (ec_request_add_block2(g_ctx.cli, g_ctx.bopt.block_no,
                    0, g_ctx.bopt.block_sz) == -1);
    }

    /* In case of POST/PUT load payload from file (if not NULL). */
    if ((g_ctx.method == EC_POST || g_ctx.method == EC_PUT) && g_ctx.pfn)
    {
        dbg_err_if (u_load_file(g_ctx.pfn, 0, (char **) &payload, &payload_sz));
        dbg_err_if (ec_request_set_payload(g_ctx.cli, payload, payload_sz));
        u_free(payload), payload = NULL;
    }

    CHAT("sending request to %s", g_ctx.uri);

    /* 
    dbg_err_if (ec_request_add_if_match(cli, etag, sizeof etag));
    dbg_err_if (ec_request_add_accept(g_ctx.cli, EC_MT_TEXT_PLAIN));
    dbg_err_if (ec_request_add_accept(g_ctx.cli, EC_MT_APPLICATION_JSON));
    */

    dbg_err_if (ec_request_send(g_ctx.cli, cb, NULL, &g_ctx.app_tout));

    return event_base_dispatch(g_ctx.base);
err:
    if (payload)
        u_free(payload);
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
        { EC_GET, "get" }, 
        { EC_POST, "post" }, 
        { EC_PUT, "put" }, 
        { EC_DELETE, "delete" }
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

int client_set_model(const char *s)
{
    dbg_return_if (s == NULL, -1);

    if (!strcasecmp(s, "non"))
    {
        g_ctx.model = EC_NON; 
        return 0;
    }
    else if (!strcasecmp(s, "con"))
    {
        g_ctx.model = EC_CON; 
        return 0;
    }

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

int client_set_payload_file(const char *s)
{
    dbg_return_if (s == NULL, -1);
    
    g_ctx.pfn = s;

    return 0;
}

int client_save_to_file(const uint8_t *pl, size_t pl_sz)
{
    FILE *fp = NULL;

    if (g_ctx.ofn[0] == '-')
    {
        con_err_sifm (fwrite(pl, pl_sz, 1, stdout) != 1,
                "could not write to %s", g_ctx.ofn);
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
