#ifndef _EC_FLOW_H_
#define _EC_FLOW_H_

#include <u/libu.h>
#include <event2/util.h>

#include "evcoap_enums.h"
#include "evcoap_net.h"

typedef struct
{
    ec_conn_t conn;
    ec_method_t method;
    ec_rc_t resp_code;
    u_uri_t *uri;
    char urlstr[U_URI_STRMAX];  /* URI string \minus the query */
    uint8_t token[8];
    size_t token_sz;
} ec_flow_t;

int ec_flow_save_token(ec_flow_t *flow, uint8_t *tok, size_t tok_sz);
int ec_flow_save_url(ec_flow_t *flow, u_uri_t *url);
int ec_flow_get_token(ec_flow_t *flow, uint8_t token[8], size_t *token_sz);
const char *ec_flow_get_urlstr(ec_flow_t *flow);
ec_method_t ec_flow_get_method(ec_flow_t *flow);
ec_rc_t ec_flow_get_resp_code(ec_flow_t *flow);
int ec_flow_set_method(ec_flow_t *flow, ec_method_t method);
int ec_flow_set_resp_code(ec_flow_t *flow, ec_rc_t rc);

#endif  /* !_EC_FLOW_H_ */
