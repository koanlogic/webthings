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

void ec_net_pullup_all(evutil_socket_t sd, ec_pdu_handler_t pdu_proc, void *a);

ev_ssize_t ec_net_pullup(evutil_socket_t sd, ev_uint8_t *b, size_t b_sz,
        int *flags, struct sockaddr *peer, ev_socklen_t *peerlen, int *e);

int ec_net_send(ev_uint8_t h[4], ev_uint8_t *o, size_t o_sz, ev_uint8_t *p,
        size_t p_sz, evutil_socket_t sd, struct sockaddr_storage *d,
        ev_socklen_t d_sz);

#endif  /* !_EC_NET_H_ */
