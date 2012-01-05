#include <evcoap.h>
#include <u/libu.h>

int facility = LOG_LOCAL0;

int well_known_cb(ec_server_t *srv, void *args)
{
    ec_t *coap = ec_server_get_base(srv);

    u_con("%s", __func__);

    return 0;
}

int fallback(ec_server_t *srv, void *args)
{
    ec_t *coap = ec_server_get_base(srv);

    u_con("%s", __func__);

    return 0;
}

int main(void)
{
    ec_t *coap = NULL;
    struct event_base *base = NULL;
    struct evdns_base *dns = NULL;
    const char *wkc = "/.well-known/core";

    con_err_if ((base = event_base_new()) == NULL);
    con_err_if ((dns = evdns_base_new(base, 1)) == NULL);
    con_err_if ((coap = ec_init(base, dns)) == NULL);

    con_err_if (ec_bind_socket(coap, "127.0.0.1", 50505));
/*    con_err_if (ec_bind_socket(coap, "[::1]", EC_COAP_DEFAULT_PORT)); */
    con_err_if (ec_bind_socket(coap, "[::1]", 50505));

    con_err_if (ec_register_url(coap, wkc, well_known_cb, NULL));
    con_err_if (ec_register_any(coap, fallback, NULL));

    (void) event_base_dispatch(base);

    return EXIT_SUCCESS;
err:
    if (base)
        event_base_free(base);
    if (dns)
        evdns_base_free(dns, 0);
    if (coap)
        ec_term(coap);

    return EXIT_FAILURE;
}
