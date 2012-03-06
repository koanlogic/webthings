#ifndef _EC_CLI_H_
#define _EC_CLI_H_

#include <event2/util.h>
#include <event2/dns.h>

#include "evcoap_enums.h"
#include "evcoap_pdu.h"

struct ec_s;
struct ec_client_s;

typedef void (*ec_client_cb_t)(struct ec_client_s *cli);

/* Take care of requests to multicast resources. */
typedef struct ec_res_set_s
{
    size_t nres;
    TAILQ_HEAD(, ec_pdu_s) bundle;
} ec_res_set_t;

struct ec_cli_timer_s
{
    size_t retries_left;    /* >1 for counted timer (decremented when fires.) */
    struct event *evti;     /* timer event. */
    struct timeval tout;    /* timer interval. */
};
typedef struct ec_cli_timer_s ec_cli_timer_t;

/* Client timers. */
struct ec_cli_timers_s
{
#define EC_TIMERS_APP_TOUT  60  /* Default is one minute. */
    ec_cli_timer_t app;         /* Application level timer. */
    ec_cli_timer_t coap;        /* CoAP internal retransmission timers. */
    ec_cli_timer_t obs;         /* Observe timer -- driven by the server. */
};
typedef struct ec_cli_timers_s ec_cli_timers_t;

struct ec_cli_obs_s
{
    bool on;            /* True if this ctx is associated to an observation. */
    uint16_t last_cnt;  /* Last counter received. */
    time_t last_ts;     /* Timestamp of last received notification. */
};
typedef struct ec_cli_obs_s ec_cli_obs_t;

/* Client transaction context. */
struct ec_client_s
{
    struct ec_s *base;
    struct evdns_getaddrinfo_request *dns_req;
    ec_client_cb_t cb;
    void *cb_args;
    ec_cli_state_t state;
    ec_cli_obs_t observe;
    ec_cli_timers_t timers;
    ec_flow_t flow;
    ec_pdu_t req;
    ec_res_set_t res_set;
    TAILQ_ENTRY(ec_client_s) next;
};
typedef struct ec_client_s ec_client_t;

ec_client_t *ec_client_new(struct ec_s *coap, ec_method_t m, const char *uri, 
        ec_msg_model_t mm, const char *proxy_host, uint16_t proxy_port);
void ec_client_free(ec_client_t *cli);

/* Setters. */
int ec_client_set_proxy(ec_client_t *cli, const char *host, uint16_t port);
int ec_client_set_method(ec_client_t *cli, ec_method_t m);
int ec_client_set_uri(ec_client_t *cli, const char *uri);
int ec_client_set_msg_model(ec_client_t *cli, bool is_con);
bool ec_client_set_state(ec_client_t *cli, ec_cli_state_t state);
ec_pdu_t *ec_client_get_request_pdu(ec_client_t *cli);
ec_opts_t *ec_client_get_request_options(ec_client_t *cli);

/* Getters. */
struct ec_s *ec_client_get_base(ec_client_t *cli);
ec_cli_state_t ec_client_get_state(ec_client_t *cli);
void *ec_client_get_args(ec_client_t *cli);
ec_pdu_t *ec_client_get_response_pdu(ec_client_t *cli);         /* unicast */
ec_opts_t *ec_client_get_response_options(ec_client_t *cli);    /* unicast */

int ec_client_go(ec_client_t *cli, ec_client_cb_t cb, void *cb_args,
        struct timeval *tout);
void ec_client_input(evutil_socket_t sd, short u, void *arg);
int ec_client_handle_empty_pdu(ec_client_t *cli, uint8_t t, uint16_t mid);
int ec_client_register(ec_client_t *cli);
int ec_client_unregister(ec_client_t *cli);

/* Timers handling. */
int ec_cli_start_app_timer(ec_client_t *cli);
int ec_cli_stop_app_timer(ec_client_t *cli);
int ec_cli_start_coap_timer(ec_client_t *cli);
int ec_cli_restart_coap_timer(ec_client_t *cli);
int ec_cli_stop_coap_timer(ec_client_t *cli);

/* Response set handling. */
int ec_res_set_add(ec_res_set_t *rset, ec_pdu_t *pdu);
int ec_res_set_init(ec_res_set_t *rset);
void ec_res_set_clear(ec_res_set_t *rset);

#endif  /* !_EC_CLI_H_ */
