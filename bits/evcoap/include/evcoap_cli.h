#ifndef _EC_CLI_H_
#define _EC_CLI_H_

#include <event2/util.h>
#include <event2/dns.h>

#include "evcoap_enums.h"
#include "evcoap_pdu.h"

struct ec_s;
struct ec_client_s;

typedef void (*ec_client_cb_t)(struct ec_client_s *cli, void *args);

/* Take care of requests to multicast resources. */
typedef struct ec_res_set_s
{
    size_t nres;
    TAILQ_HEAD(, ec_pdu_s) bundle;
} ec_res_set_t;

struct ec_client_s
{
    struct ec_s *base;
    struct evdns_getaddrinfo_request *dns_req;
    ec_client_cb_t cb;
    void *cb_args;
    ec_cli_state_t state;
    ec_flow_t flow;
    ec_pdu_t req;
    ec_res_set_t res_set;
    TAILQ_ENTRY(ec_client_s) next;
};

typedef struct ec_client_s ec_client_t;

ec_client_t *ec_client_new(struct ec_s *coap, ec_method_t m, const char *uri, 
        ec_msg_model_t mm, const char *proxy_host, ev_uint16_t proxy_port);

void ec_client_free(ec_client_t *cli);

int ec_client_set_proxy(ec_client_t *cli, const char *host, ev_uint16_t port);

int ec_client_set_method(ec_client_t *cli, ec_method_t m);

int ec_client_set_uri(ec_client_t *cli, const char *uri);

int ec_client_set_msg_model(ec_client_t *cli, bool is_con);

int ec_client_go(ec_client_t *cli, ec_client_cb_t cb, void *cb_args);

void ec_client_set_state(ec_client_t *cli, ec_cli_state_t state);

int ec_client_register(ec_client_t *cli);

/* Getters. */
struct ec_s *ec_client_get_base(ec_client_t *cli);

ec_cli_state_t ec_client_get_state(ec_client_t *cli);

void ec_client_input(evutil_socket_t sd, short u, void *arg);

#endif  /* !_EC_CLI_H_ */
