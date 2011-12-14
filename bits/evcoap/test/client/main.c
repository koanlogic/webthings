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

#if 0
    struct evcoap_pdu *pdu = NULL;
    const char *proxy_uri = "coap://localhost.home./set?var=val",
               *uri_host = "actuator.things.",
               *etag = "ABCD1234",
               *tok = "1234abcd",
               *location_path = "/set",
               *location_query = "a=b&c=d",
               *uri_query = "a=b&c=d&e=f",
               *uri_path = "/set";
    size_t etag_len = strlen(etag),
           tok_len = strlen(tok);
    
    con_err_if ((pdu = evcoap_pdu_new_empty()) == NULL);
    con_err_if (evcoap_pdu_add_observe(pdu, 23214));
    con_err_if (evcoap_pdu_add_proxy_uri(pdu, proxy_uri));
    con_err_if (evcoap_pdu_add_etag(pdu, (const ev_uint8_t *) etag, etag_len));
    con_err_if (evcoap_pdu_add_max_age(pdu, 4000000000));
    con_err_if (evcoap_pdu_add_location_path(pdu, location_path));
    con_err_if (evcoap_pdu_add_uri_host(pdu, uri_host));
    con_err_if (evcoap_pdu_add_content_type(pdu, EVCOAP_CT_TEXT_PLAIN));
    con_err_if (evcoap_pdu_add_uri_query(pdu, uri_query));
    con_err_if (evcoap_pdu_add_location_query(pdu, location_query));
    con_err_if (evcoap_pdu_add_uri_path(pdu, uri_path));
    con_err_if (evcoap_pdu_add_token(pdu, (const ev_uint8_t *) tok, tok_len));
    con_err_if (evcoap_pdu_add_accept(pdu, EVCOAP_CT_APPLICATION_JSON));
    con_err_if (evcoap_pdu_add_uri_port(pdu, 65535));
    con_err_if (evcoap_pdu_add_if_match(pdu, (const ev_uint8_t *) etag, 
                etag_len));
    con_err_if (evcoap_pdu_add_if_none_match(pdu));
//    con_err_if (evcoap_pdu_add_max_ofe(pdu, 4000000000));

    con_err_if (evcoap_opts_encode(pdu));

    return EXIT_SUCCESS;
err:
    return EXIT_FAILURE;
#endif

