#include <evcoap.h>
#include <u/libu.h>

int facility = LOG_LOCAL0;

#define DEFAULT_CONF    "./coap-server.conf"

typedef struct
{
    ec_t *coap;
    struct event_base *base;
    struct evdns_base *dns;
    const char *conf;
} ctx_t;

ctx_t g_ctx = {
    .coap = NULL,
    .base = NULL,
    .dns = NULL,
    .conf = DEFAULT_CONF
};

void usage(const char *prog);
int evcoap_server_init(void);
int evcoap_server_run(void);
void evcoap_server_term(void);
int evcoap_server_bind(u_config_t *cfg);
int parse_addr(const char *ap, char *a, size_t a_sz, ev_uint16_t *p);

int main(int ac, char *av[])
{
    int c;
    u_config_t *cfg = NULL;

    while ((c = getopt(ac, av, "hf:")) != -1)
    {
        switch (c)
        {
            case 'f':
                g_ctx.conf = optarg;
                break;
            case 'h':
            default: 
                usage(av[0]);
        }
    }

    /* Load configuration from file. */
    con_err_ifm (u_config_load_from_file(g_ctx.conf, &cfg),
            "error loading %s", g_ctx.conf);

    con_err_ifm (evcoap_server_init(), "evcoap initialization failed");
    con_err_ifm (evcoap_server_bind(cfg), "server socket setup failed");
    //evcoap_server_register_uri()

    //evcoap_server_register_wkc()
    //evcoap_server_register_fallback()

    con_err_ifm (evcoap_server_run(), "server run failed");

    return EXIT_SUCCESS;
err:
    return EXIT_FAILURE;
}

int evcoap_server_init(void)
{
    dbg_err_if ((g_ctx.base = event_base_new()) == NULL);
    dbg_err_if ((g_ctx.dns = evdns_base_new(g_ctx.base, 1)) == NULL);
    dbg_err_if ((g_ctx.coap = ec_init(g_ctx.base, g_ctx.dns)) == NULL);

    return 0;
err:
    evcoap_server_term();
    return -1;
}

int evcoap_server_run(void)
{
    return event_base_dispatch(g_ctx.base);
}

void evcoap_server_term(void)
{
    if (g_ctx.coap)
        ec_term(g_ctx.coap);

    if (g_ctx.dns)
        evdns_base_free(g_ctx.dns, 0);

    if (g_ctx.base)
        event_base_free(g_ctx.base);

    return;
}

int evcoap_server_bind(u_config_t *cfg)
{
    int i;
    u_config_t *addr;
    const char *v;
    char a[256];
    ev_uint16_t port;

    dbg_return_if (cfg == NULL, -1);

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

int parse_addr(const char *ap, char *a, size_t a_sz, ev_uint16_t *p)
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
        *p = (ev_uint16_t) tmp;
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
        "       -f <conf file>      (default is "DEFAULT_CONF")         \n"
        "                                                               \n"
        ;

    u_con(us, prog);

    exit(EXIT_FAILURE);
    return;
}
