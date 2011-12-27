#ifndef _EC_FLOW_H_
#define _EC_FLOW_H_

#include <u/libu.h>
#include <event2/util.h>

#include "evcoap_enums.h"
#include "evcoap_pdu.h"
#include "evcoap_net.h"

typedef struct
{
    ec_conn_t conn;

    ec_method_t method;
    u_uri_t *uri;
    ec_rc_t resp_code;

    ev_uint8_t token[8];
    size_t token_sz;
} ec_flow_t;

#endif  /* !_EC_FLOW_H_ */
