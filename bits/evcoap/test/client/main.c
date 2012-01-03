#include <evcoap.h>
#include <u/libu.h>

int facility = LOG_LOCAL0;

void cb(ec_client_t *cli)
{
    ec_t *coap = ec_client_get_base(cli);
    ec_cli_state_t fsm_state = ec_client_get_state(cli);

    u_con("GOT IT!!!");

    ec_loopbreak(coap);
}

int main(void)
{
    ec_t *coap = NULL;
    ec_client_t *cli = NULL;
    struct event_base *base = NULL;
    struct evdns_base *dns = NULL;
    struct timeval tout = {.tv_sec = 2, .tv_usec = 0};
    const char *uri = "coap://[::1]/.well-known/core";
    const ev_uint8_t etag[] = { 0xde, 0xad, 0xbe, 0xef };

    con_err_if ((base = event_base_new()) == NULL);
    con_err_if ((dns = evdns_base_new(base, 1)) == NULL);
    con_err_if ((coap = ec_init(base, dns)) == NULL);

    con_err_if ((cli = ec_request_new(coap, EC_GET, uri, EC_NON)) == NULL);

    /* con_err_if (ec_request_add_if_match(cli, etag, sizeof etag)); */
    con_err_if (ec_request_add_accept(cli, EC_MT_TEXT_PLAIN));
    con_err_if (ec_request_add_accept(cli, EC_MT_APPLICATION_JSON));

    con_err_if (ec_request_send(cli, cb, NULL, &tout));

    return event_base_dispatch(base);
err:
    return EXIT_FAILURE;
}
