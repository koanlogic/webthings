#include <evcoap.h>
#include <u/libu.h>

int facility = LOG_LOCAL0;

evcoap_cb_status_t coap_well_known(struct evcoap_pdu *pdu, const char *path,
        void *u)
{
    u_unused_args(pdu, u);
    u_con("(%s) TODO serve '%s'", __func__, path);
    return EVCOAP_CB_STATUS_RESP_SENT;
}

evcoap_cb_status_t coap_serve_con(struct evcoap_pdu *pdu, const char *path,
        void *u)
{
    u_unused_args(pdu, u);
    u_con("(%s) TODO serve '%s'", __func__, path);
    return EVCOAP_CB_STATUS_ACK_AUTO;
}

evcoap_cb_status_t coap_serve_non(struct evcoap_pdu *pdu, const char *path,
        void *u)
{
    u_unused_args(pdu, u);
    u_con("(%s) TODO serve '%s'", __func__, path);
    return EVCOAP_CB_STATUS_RESP_SENT;
}

void coap_gen_callback(struct evcoap_pdu *pdu, const char *path, void *u)
{
    u_unused_args(pdu, u);
    u_con("(%s) TODO serve '%s'", __func__, path);
}

int main(void)
{
    struct event_base *eb = NULL;
    struct evdns_base *ed = NULL;
    struct evcoap *ec = NULL;

    dbg_err_if ((eb = event_base_new()) == NULL);
    dbg_err_if ((ed = evdns_base_new(eb, 1)) == NULL);

    dbg_err_if ((ec = evcoap_new(eb, ed)) == NULL);

    dbg_err_if (evcoap_bind_socket(ec, "127.0.0.1", 50505, 0));
    dbg_err_if (evcoap_bind_socket(ec, "[::1]", COAP_DEFAULT_SERVER_PORT, 0));
    dbg_err_if (evcoap_set_cb_ex(ec, "/con/*", coap_serve_con, NULL,
                &(struct timeval){.tv_sec = 5, .tv_usec = 0}));
    dbg_err_if (evcoap_set_cb(ec, "/non/*", coap_serve_non, NULL));
    dbg_err_if (evcoap_set_cb(ec, "/.well-known/core", coap_well_known, NULL));
    dbg_err_if (evcoap_set_gencb(ec, coap_gen_callback, NULL));

    (void) event_base_dispatch(eb);

    return EXIT_SUCCESS;
err:
    if (eb)
        event_base_free(eb);
    if (ed)
        evdns_base_free(ed, 0);
    if (ec)
        evcoap_free(ec);

    return EXIT_FAILURE;
}
