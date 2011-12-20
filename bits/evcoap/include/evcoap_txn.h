#ifndef _EC_TXN_H_
#define _EC_TXN_H_

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
} ec_txn_t;

struct ec_server_s
{
    ec_srv_state_t state;
    ec_txn_t meta;
    ec_pdu_t req;
    ec_pdu_t res;
};

typedef struct ec_server_s ec_server_t;

struct ec_client_s
{
    ec_cli_state_t state;
    ec_txn_t meta;
    ec_pdu_t req;
    TAILQ_HEAD(, ec_pdu_s) res;
};

typedef struct ec_client_s ec_client_t;

ec_client_t *ec_client_new(ec_method_t m, const char *uri,
        const char *proxy_host, ev_uint16_t proxy_port);

void ec_client_free(ec_client_t *cli);

int ec_client_set_proxy(ec_client_t *cli, const char *proxy_host,
        ev_uint16_t proxy_port);

int ec_client_set_method(ec_client_t *cli, ec_method_t m);

int ec_client_set_uri(ec_client_t *cli, const char *uri);

#endif  /* !_EC_TXN_H_ */
