#include <evcoap.h>
#include <u/libu.h>

int facility = LOG_LOCAL0;

void req_basic_cb(struct evcoap_pdu *pdu, int boh, void *sarca)
{
    u_con("got response !!!");
    return;
}

int req_basic(struct evcoap *coap)
{
    struct evcoap_pdu *pdu = NULL;

    con_err_if ((pdu = evcoap_pdu_new_empty()) == NULL);

    con_err_if (evcoap_pdu_req_set_header(pdu, EVCOAP_PDU_TYPE_NON, 
                EVCOAP_METHOD_GET));

    /* Force 15 chars limit (extended length option.) */
    con_err_if (evcoap_pdu_add_uri_host(pdu, "localhost.home."));
    con_err_if (evcoap_pdu_add_uri_path(pdu, "path-segment1"));

    con_err_if (evcoap_send_request(coap, pdu, req_basic_cb, NULL, NULL));

    return 0;
err:
    return -1;
}

int main(void)
{
    struct evcoap *coap = NULL;
    struct event_base *base = NULL;
    struct evdns_base *dns = NULL;

    dbg_err_if ((base = event_base_new()) == NULL);
    dbg_err_if ((dns = evdns_base_new(base, 1)) == NULL);
    dbg_err_if ((coap = evcoap_new(base, dns)) == NULL);

    con_err_if (req_basic(coap));

    return event_base_dispatch(base);
err:
    return EXIT_FAILURE;
}
