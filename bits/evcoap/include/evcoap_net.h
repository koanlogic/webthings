#ifndef _EC_NET_H_
#define _EC_NET_H_

#include <stdbool.h>

#include "event2/util.h"

#ifndef EC_COAP_MAX_REQ_SIZE
#define EC_COAP_MAX_REQ_SIZE 1500
#endif  /* !EC_COAP_MAX_REQ_SIZE */

typedef struct
{
    evutil_socket_t socket;
    struct event *ev_input;
    struct sockaddr_storage us;
    ev_socklen_t us_len;
    bool is_multicast;
    bool is_confirmable;
    bool use_proxy;
    char proxy_addr[512];
    ev_uint16_t proxy_port;

    /* TODO The security context goes here. */

} ec_conn_t;

/* TODO change this to accomodate client/server needs. */
typedef int (*ec_pdu_handler_t)(ev_uint8_t *, size_t, void *);

evutil_socket_t ec_net_bind_socket(struct sockaddr_storage *ss, int ss_len);

ev_ssize_t ec_net_recvmsg(evutil_socket_t sd, ev_uint8_t *b, size_t b_sz,
        int *flags, struct sockaddr *peer, ev_socklen_t *peerlen);

void ec_net_dispatch(evutil_socket_t sd, ec_pdu_handler_t pdu_proc, void *arg);

ev_ssize_t ec_net_pullup(evutil_socket_t sd, ev_uint8_t *b, size_t b_sz,
        int *flags, struct sockaddr *peer, ev_socklen_t *peerlen, int *e);

#endif  /* !_EC_NET_H_ */
