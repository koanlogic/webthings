#ifndef _EC_PDU_H_
#define _EC_PDU_H_

#include <u/libu.h>
#include <event2/util.h>

#include "evcoap_opt.h"
#include "evcoap_flow.h"

struct ec_pdu_s
{
    ev_uint8_t hdr[4];
    /* TODO decoded MID ? */

    ev_uint8_t *payload;
    size_t payload_sz;

    struct ec_opts_s opts;

    struct sockaddr_storage peer;
    ev_socklen_t peer_len;

    ec_flow_t *parent_flow;

    TAILQ_ENTRY(ec_pdu_s) next;
};

typedef struct ec_pdu_s ec_pdu_t;

int ec_pdu_set_payload(ec_pdu_t *pdu, ev_uint8_t *payload, size_t sz);
int ec_pdu_set_flow(ec_pdu_t *pdu, ec_flow_t *flow);
int ec_pdu_init_options(ec_pdu_t *pdu);
int ec_pdu_send(ec_pdu_t *pdu, const struct sockaddr_storage *dest);
int ec_pdu_encode(ec_pdu_t *pdu);

#endif  /* !_EC_PDU_H_ */
