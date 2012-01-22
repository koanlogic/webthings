#ifndef _EC_PDU_H_
#define _EC_PDU_H_

#include <u/libu.h>
#include <event2/util.h>

#include "evcoap_opt.h"
#include "evcoap_flow.h"

typedef struct ec_hdr_s
{
    ev_uint8_t t, oc, code;
    ev_uint16_t mid;
} ec_hdr_t;

struct ec_pdu_s
{
    ev_uint8_t hdr[EC_COAP_HDR_SIZE];
    ec_hdr_t hdr_bits;

    ev_uint16_t mid;

    ev_uint8_t *payload;
    size_t payload_sz;

    struct ec_opts_s opts;

    struct sockaddr_storage peer;
    ev_socklen_t peer_len;

    /* Set in reply PDU to refer to the message that initiated the exchange. */
    struct ec_pdu_s *sibling;

    /* Message flow. */
    ec_flow_t *flow;

    TAILQ_ENTRY(ec_pdu_s) next;
};

typedef struct ec_pdu_s ec_pdu_t;

int ec_pdu_set_payload(ec_pdu_t *pdu, ev_uint8_t *payload, size_t sz);
int ec_pdu_set_flow(ec_pdu_t *pdu, ec_flow_t *flow);
int ec_pdu_set_peer(ec_pdu_t *pdu, const struct sockaddr_storage *peer,
        size_t peer_len);
int ec_pdu_set_sibling(ec_pdu_t *pdu, ec_pdu_t *sibling);
int ec_pdu_get_type(ec_pdu_t *pdu, ev_uint8_t *t);
int ec_pdu_get_mid(ec_pdu_t *pdu, ev_uint16_t *mid);
int ec_pdu_init_options(ec_pdu_t *pdu);
int ec_pdu_send(ec_pdu_t *pdu);
int ec_pdu_encode_response_separate(ec_pdu_t *pdu);
int ec_pdu_encode_response_piggyback(ec_pdu_t *pdu);
int ec_pdu_encode_response_ack(ec_pdu_t *pdu);
int ec_pdu_encode_response_rst(ec_pdu_t *pdu);
int ec_pdu_encode_request(ec_pdu_t *pdu);
int ec_pdu_decode_header(ec_pdu_t *pdu, const ev_uint8_t *raw, size_t raw_sz);
ec_pdu_t *ec_pdu_new_empty(void);
void ec_pdu_free(ec_pdu_t *pdu);

#endif  /* !_EC_PDU_H_ */
