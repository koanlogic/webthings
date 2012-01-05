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
    ec_pdu_t *req;
    ec_pdu_t *res;
    TAILQ_ENTRY(ec_server_s) next;
};

typedef struct ec_server_s ec_server_t;

ec_server_t *ec_server_new(struct ec_s *coap, evutil_socket_t sd);
void ec_server_input(evutil_socket_t sd, short u, void *arg);
int ec_server_handle_pdu(ev_uint8_t *raw, size_t raw_sz, void *arg);
void ec_server_set_state(ec_server_t *srv, ec_srv_state_t state);
int ec_server_set_req(ec_server_t *srv, ec_pdu_t *req);
struct ec_s *ec_server_get_base(ec_server_t *srv);

#endif  /* !_EC_SRV_H_ */
