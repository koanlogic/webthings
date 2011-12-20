#ifndef _EC_PDU_H_
#define _EC_PDU_H_

#include <event2/util.h>
#include "evcoap_opt.h"

struct ec_pdu_s
{
    ev_uint8_t hdr[4];
    /* TODO decoded MID ? */

    ev_uint8_t *payload;
    size_t payload_sz;

    struct ec_opts_s opts;
};

typedef struct ec_pdu_s ec_pdu_t;

int ec_pdu_set_payload(ec_pdu_t *pdu, ev_uint8_t *payload, size_t sz);

#endif  /* !_EC_PDU_H_ */
