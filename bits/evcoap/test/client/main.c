#include <unistd.h>
#include <evcoap.h>
#include <u/libu.h>

int facility = LOG_LOCAL0;

#define DEFAULT_URI "coap://[::1]/.well-known/core"

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
    ev_uint8_t etag[4];
} ctx_t;

ctx_t g_ctx = {
    .coap = NULL,
    .cli = NULL,
    .base = NULL,
    .dns = NULL,
    .uri = DEFAULT_URI,
    .method = EC_GET,
    .model = EC_NON,
    .app_tout = { .tv_sec = EC_TIMERS_APP_TOUT, .tv_usec = 0 },
    .etag = { 0xde, 0xad, 0xbe, 0xef }
};

void usage(const char *prog);
int evcoap_client_init(void);
int evcoap_client_run(void);
void evcoap_client_term(void);
int evcoap_client_set_uri(const char *s);
int evcoap_client_set_method(const char *s);
int evcoap_client_set_model(const char *s);
void cb(ec_client_t *cli);

/*
 * TODO
 */ 
int main(int ac, char *av[])
{
    int c;

    while ((c = getopt(ac, av, "hu:m:M")) != -1)
    {
        switch (c)
        {
            case 'u': /* .uri */
                if (evcoap_client_set_uri(optarg))
                    usage(av[0]);
                break;
            case 'm': /* .method */
                if (evcoap_client_set_method(optarg))
                    usage(av[0]);
                break;
            case 'M': /* .model */
                if (evcoap_client_set_model(optarg))
                    usage(av[0]);
                break;
            case 'h':
            default:
                usage(av[0]);
        }
    }

    con_err_if (evcoap_client_init());
    con_err_if (evcoap_client_run());

    evcoap_client_term();
    return EXIT_SUCCESS;
err:
    evcoap_client_term();
    return EXIT_FAILURE;
}

void cb(ec_client_t *cli)
{
    ec_t *coap = ec_client_get_base(cli);
    ec_cli_state_t fsm_state = ec_client_get_state(cli);

    con_err_ifm (fsm_state != EC_CLI_STATE_REQ_DONE, 
            "request failed: %s", ec_cli_state_str(fsm_state));

    u_con("got response !");

    /* Fall through. */
err:
    ec_loopbreak(coap);
    return;
}

void usage(const char *prog)
{
    const char *us = 
        "Usage: %s [opts]                                               \n"
        "                                                               \n"
        "   where opts is one of:                                       \n"
        "       -h  this help                                           \n"
        "       -m <GET|POST|PUT|DELETE>    (default is GET)            \n"
        "       -M <CON|NON>                (default is NON)            \n"
        "       -u <uri>                    (default is "DEFAULT_URI")  \n"
        "                                                               \n"
        ;

    u_con(us, prog);

    exit(EXIT_FAILURE);
}

int evcoap_client_init(void)
{
    dbg_err_if ((g_ctx.base = event_base_new()) == NULL);
    dbg_err_if ((g_ctx.dns = evdns_base_new(g_ctx.base, 1)) == NULL);
    dbg_err_if ((g_ctx.coap = ec_init(g_ctx.base, g_ctx.dns)) == NULL);

    return 0;
err:
    evcoap_client_term();
    return -1;
}

void evcoap_client_term(void)
{
    if (g_ctx.coap)
        ec_term(g_ctx.coap);

    return;
}

int evcoap_client_run(void)
{
    dbg_err_if ((g_ctx.cli = ec_request_new(g_ctx.coap, g_ctx.method, 
                    g_ctx.uri, g_ctx.model)) == NULL);

    /* 
    dbg_err_if (ec_request_add_if_match(cli, etag, sizeof etag));
    dbg_err_if (ec_request_add_accept(g_ctx.cli, EC_MT_TEXT_PLAIN));
    dbg_err_if (ec_request_add_accept(g_ctx.cli, EC_MT_APPLICATION_JSON));
    */

    dbg_err_if (ec_request_send(g_ctx.cli, cb, NULL, &g_ctx.app_tout));

    return event_base_dispatch(g_ctx.base);
err:
    return -1;
}

int evcoap_client_set_uri(const char *s)
{
    dbg_return_if (s == NULL, -1);
    g_ctx.uri = s;
    return 0;
}

int evcoap_client_set_method(const char *s)
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

int evcoap_client_set_model(const char *s)
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


