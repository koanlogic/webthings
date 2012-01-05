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

    ec_flow_t *flow;

    TAILQ_ENTRY(ec_pdu_s) next;
};

typedef struct ec_pdu_s ec_pdu_t;

int ec_pdu_set_payload(ec_pdu_t *pdu, ev_uint8_t *payload, size_t sz);
int ec_pdu_set_flow(ec_pdu_t *pdu, ec_flow_t *flow);
int ec_pdu_init_options(ec_pdu_t *pdu);
int ec_pdu_send(ec_pdu_t *pdu, struct sockaddr_storage *d, ev_socklen_t d_sz);
int ec_pdu_encode(ec_pdu_t *pdu);
ec_pdu_t *ec_pdu_new_empty(void);
int ec_pdu_decode_header(ec_pdu_t *pdu, const ev_uint8_t *raw, size_t raw_sz);

#endif  /* !_EC_PDU_H_ */
