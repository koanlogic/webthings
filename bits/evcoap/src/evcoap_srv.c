#include <u/libu.h>
#include "evcoap_srv.h"
#include "evcoap_base.h"

ec_server_t *ec_server_new(struct ec_s *coap, evutil_socket_t sd)
{
    return 0;
}

void ec_server_input(evutil_socket_t sd, short u, void *arg)
{
    ec_t *coap = (ec_t *) arg;

    u_unused_args(u);

    u_con("%s", __func__);
    ec_net_dispatch(sd, ec_server_handle_pdu, coap);
}

int ec_server_handle_pdu(ev_uint8_t *raw, size_t raw_sz, void *arg)
{
    u_con("%s", __func__);
    return 0;
}

