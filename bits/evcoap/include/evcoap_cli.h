#ifndef _EC_CLI_H_
#define _EC_CLI_H_

#include <event2/util.h>

#include "evcoap_enums.h"
#include "evcoap_pdu.h"

struct ec_client_s
{
    ec_cli_state_t state;
    ec_flow_t flow;
    ec_pdu_t req;
    TAILQ_HEAD(, ec_pdu_s) res;
    TAILQ_ENTRY(ec_client_s) next;
};

typedef struct ec_client_s ec_client_t;

ec_client_t *ec_client_new(ec_method_t m, const char *uri, ec_msg_model_t mm,
        const char *proxy_host, ev_uint16_t proxy_port);

void ec_client_free(ec_client_t *cli);

int ec_client_set_proxy(ec_client_t *cli, const char *proxy_host,
        ev_uint16_t proxy_port);

int ec_client_set_method(ec_client_t *cli, ec_method_t m);

int ec_client_set_uri(ec_client_t *cli, const char *uri);

int ec_client_set_msg_model(ec_client_t *cli, bool is_con);

#endif  /* !_EC_CLI_H_ */
