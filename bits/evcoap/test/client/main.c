#include <evcoap.h>
#include <u/libu.h>

int facility = LOG_LOCAL0;

void req_basic_cb(struct evcoap *coap, struct evcoap_pdu *pdu, 
        evcoap_send_status_t status, void *args)
{
    const ev_uint8_t *p = NULL;
    size_t plen;

    con_err_if (status != EVCOAP_SEND_STATUS_OK);

    u_con("got response with code %u", evcoap_pdu_get_resp_status(pdu));

    switch (evcoap_pdu_get_resp_status(pdu))
    {
        case EVCOAP_RESP_CODE_CONTENT:
            if ((p = evcoap_pdu_get_payload(pdu, &plen)))
            {
                char s[plen + 1];

                (void) strlcpy(s, (const char *) p, sizeof s);

                u_con("payload: %s", s);
            }
        default:
            break;
    }

err:
    evcoap_loopbreak(coap);
    return;
}

/* TODO simplify */
#define EVCOAP_NON  EVCOAP_PDU_TYPE_NON
#define EVCOAP_GET  EVCOAP_METHOD_GET

int req_basic(struct evcoap *coap)
{
    struct evcoap_pdu *pdu = NULL;

    /* Force 15 chars limit on Uri-Host (extended length option.) */
    con_err_if ((pdu = evcoap_request_new(EVCOAP_NON, EVCOAP_GET,
                    "coap://localhost.home.:5684/.well-known/core")) == NULL);

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
