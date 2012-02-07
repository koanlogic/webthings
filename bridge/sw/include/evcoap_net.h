#ifndef _EC_NET_H_
#define _EC_NET_H_

#include <stdbool.h>
#include "event2/util.h"
#include "evcoap_enums.h"

typedef struct
{
    evutil_socket_t socket;
    struct event *ev_input;
    struct sockaddr_storage us;
    bool is_multicast;
    char is_confirmable;    /* 0: unset, 1: CON, 2: NON */
    bool use_proxy;
    char proxy_addr[512];
    ev_uint16_t proxy_port;

    /* TODO The security context goes here. */

} ec_conn_t;

/* PDU handler interface (both client and server.) */
typedef int (*ec_pdu_handler_t)(ev_uint8_t *, size_t, int,
        struct sockaddr_storage *, void *);

evutil_socket_t ec_net_bind_socket(struct sockaddr_storage *ss, int ss_len);

ev_ssize_t ec_net_recvmsg(evutil_socket_t sd, ev_uint8_t *b, size_t b_sz,
        int *flags, struct sockaddr *peer, ev_socklen_t *peerlen);

void ec_net_pullup_all(evutil_socket_t sd, ec_pdu_handler_t pdu_proc, void *a);

ev_ssize_t ec_net_pullup(evutil_socket_t sd, ev_uint8_t *b, size_t b_sz,
        int *flags, struct sockaddr *peer, ev_socklen_t *peerlen, int *e);

int ec_net_send(ev_uint8_t h[EC_COAP_HDR_SIZE], ev_uint8_t *o, size_t o_sz,
        ev_uint8_t *p, size_t p_sz, evutil_socket_t sd,
        struct sockaddr_storage *d);

int ec_net_save_us(ec_conn_t *conn, evutil_socket_t sd);
int ec_net_set_confirmable(ec_conn_t *conn, bool is_con);
int ec_net_get_confirmable(ec_conn_t *conn, bool *is_con);

int ec_net_socklen(const struct sockaddr_storage *ss, ev_uint8_t *ss_len);

#endif  /* !_EC_NET_H_ */
