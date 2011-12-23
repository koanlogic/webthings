#ifndef _EC_SRV_H_
#define _EC_SRV_H_

#include <u/libu.h>
#include <event2/util.h>

#include "evcoap_enums.h"
#include "evcoap_pdu.h"

struct ec_s;

struct ec_server_s
{
    struct ec_s *base;
    ec_srv_state_t state;
    ec_flow_t flow;
    ec_pdu_t req;
    ec_pdu_t res;
    TAILQ_ENTRY(ec_server_s) next;
};

typedef struct ec_server_s ec_server_t;

ec_server_t *ec_server_new(struct ec_s *coap, evutil_socket_t sd);

#endif  /* !_EC_SRV_H_ */
