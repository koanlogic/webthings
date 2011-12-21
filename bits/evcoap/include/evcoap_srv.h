#ifndef _EC_SRV_H_
#define _EC_SRV_H_

#include <event2/util.h>

#include "evcoap_enums.h"
#include "evcoap_pdu.h"

struct ec_server_s
{
    ec_srv_state_t state;
    ec_flow_t flow;
    ec_pdu_t req;
    ec_pdu_t res;
    TAILQ_ENTRY(ec_server_s) next;
};

typedef struct ec_server_s ec_server_t;

#endif  /* !_EC_SRV_H_ */
