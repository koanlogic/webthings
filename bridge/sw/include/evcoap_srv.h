#ifndef _EC_SRV_H_
#define _EC_SRV_H_

#include <u/libu.h>
#include <event2/util.h>

#include "evcoap_enums.h"
#include "evcoap_pdu.h"

struct ec_s;

struct ec_servers_s
{
    TAILQ_HEAD(, ec_server_s) h;
};
typedef struct ec_servers_s ec_servers_t;

int ec_servers_init(ec_servers_t *srvs);
void ec_servers_term(ec_servers_t *srvs);


struct ec_server_s
{
    struct ec_s *base;
    ec_srv_state_t state;
    ec_flow_t flow;
    ec_pdu_t *req;
    ec_pdu_t *res;
    ec_servers_t *parent;
    TAILQ_ENTRY(ec_server_s) next;
};
typedef struct ec_server_s ec_server_t;

ec_server_t *ec_server_new(struct ec_s *coap, evutil_socket_t sd);
void ec_server_free(ec_server_t *srv);
void ec_server_input(evutil_socket_t sd, short u, void *arg);
void ec_server_set_state(ec_server_t *srv, ec_srv_state_t state);
int ec_server_set_req(ec_server_t *srv, ec_pdu_t *req);
int ec_server_send_resp(ec_server_t *srv);
int ec_server_set_msg_model(ec_server_t *srv, bool is_confirmable);
struct ec_s *ec_server_get_base(ec_server_t *srv);
const char *ec_server_get_url(ec_server_t *srv);
ec_method_t ec_server_get_method(ec_server_t *srv);
ec_pdu_t *ec_server_get_request_pdu(ec_server_t *srv);

#endif  /* !_EC_SRV_H_ */
