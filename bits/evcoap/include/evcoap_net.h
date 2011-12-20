#ifndef _EC_NET_H_
#define _EC_NET_H_

#include "event2/util.h"
#include <stdbool.h>

typedef struct
{
    evutil_socket_t sd;
    struct sockaddr_storage us;
    ev_socklen_t us_len;
    struct sockaddr_storage them;
    ev_socklen_t them_len;

    bool is_multicast;

    bool use_proxy;
    char proxy_addr[512];

    /* TODO The security context goes here. */

} ec_conn_t;

#endif  /* !_EC_NET_H_ */
