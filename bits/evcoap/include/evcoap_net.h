#ifndef _EC_NET_H_
#define _EC_NET_H_

#include <stdbool.h>

#include "event2/util.h"

typedef struct
{
    evutil_socket_t sd;
    struct sockaddr_storage us;
    ev_socklen_t us_len;
    bool is_multicast;
    bool is_confirmable;
    bool use_proxy;
    char proxy_addr[512];
    ev_uint16_t proxy_port;

    /* TODO The security context goes here. */

} ec_conn_t;

evutil_socket_t ec_net_bind_socket(struct sockaddr_storage *ss, 
        ev_socklen_t ss_len);

#endif  /* !_EC_NET_H_ */
