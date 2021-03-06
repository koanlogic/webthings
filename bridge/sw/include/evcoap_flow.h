#ifndef _EC_FLOW_H_
#define _EC_FLOW_H_

#include <u/libu.h>
#include <event2/util.h>

#include "evcoap_enums.h"
#include "evcoap_net.h"

#ifndef EC_ORIGIN_MAX
  #define EC_ORIGIN_MAX 128
#endif  /* !EC_ORIGIN_MAX */

#ifndef EC_QUERY_MAX
  #define EC_QUERY_MAX  512
#endif  /* !EC_QUERY_MAX */

typedef struct
{
    ec_conn_t conn;
    ec_method_t method;
    ec_rc_t resp_code;
    u_uri_t *uri;
    char urlstr[U_URI_STRMAX];  /* URI string \minus the query */
    char origin[U_URI_STRMAX];  /* URI string \minus path and query. */
    bool proxy_uri;             /* true if decoded URI is Proxy-URI. */
    bool is_sep;
    uint8_t token[8];
    size_t token_sz;
} ec_flow_t;

int ec_flow_init(ec_flow_t *flow);
void ec_flow_term(ec_flow_t *flow, bool do_not_close_socket);
int ec_flow_save_token(ec_flow_t *flow, const uint8_t *tok, size_t tok_sz);
int ec_flow_save_url(ec_flow_t *flow, u_uri_t *url, bool is_proxy);
int ec_flow_get_token(ec_flow_t *flow, uint8_t token[8], size_t *token_sz);
const char *ec_flow_get_urlstr(ec_flow_t *flow);
ec_method_t ec_flow_get_method(ec_flow_t *flow);
u_uri_t *ec_flow_get_uri(ec_flow_t *flow);
const char *ec_flow_get_url(ec_flow_t *flow, char url[U_URI_STRMAX], 
        bool *is_proxy);
int ec_flow_get_proxied(ec_flow_t *flow, bool *is_proxy);
ec_rc_t ec_flow_get_resp_code(ec_flow_t *flow);
int ec_flow_set_method(ec_flow_t *flow, ec_method_t method);
int ec_flow_set_resp_code(ec_flow_t *flow, ec_rc_t rc);
const char *ec_flow_get_uri_origin(ec_flow_t *flow);
const char *ec_flow_get_uri_query(ec_flow_t *flow);
const char *ec_flow_get_uri_path(ec_flow_t *flow);
int ec_flow_set_separate(ec_flow_t *flow, bool is_sep);
int ec_flow_get_separate(ec_flow_t *flow, bool *is_sep);

#endif  /* !_EC_FLOW_H_ */
