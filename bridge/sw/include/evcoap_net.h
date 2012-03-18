#ifndef _EC_NET_H_
#define _EC_NET_H_

#include <stdbool.h>
#include "event2/util.h"
#include "evcoap_enums.h"

typedef enum
{
    EC_NET_CBRC_SUCCESS = 0,
    EC_NET_CBRC_DEAD,
    EC_NET_CBRC_ERROR
} ec_net_cbrc_t;

typedef struct
{
    evutil_socket_t socket;
    struct event *ev_input;
    struct sockaddr_storage us;
    struct sockaddr_storage peer;
    bool is_multicast;
    char is_confirmable;    /* 0: unset, 1: CON, 2: NON */
    bool use_proxy;         /* true if encoded URI is Proxy-URI. */
    char proxy_addr[512];
    uint16_t proxy_port;
    /* TODO The security context goes here. */
} ec_conn_t;

int ec_conn_init(ec_conn_t *conn);
void ec_conn_term(ec_conn_t *conn);
int ec_conn_copy(const ec_conn_t *src, ec_conn_t *dst);
int ec_conn_save_us(ec_conn_t *conn, evutil_socket_t sd);
int ec_conn_save_peer(ec_conn_t *conn, const struct sockaddr_storage *peer);
int ec_conn_set_confirmable(ec_conn_t *conn, bool is_con);
int ec_conn_get_confirmable(ec_conn_t *conn, bool *is_con);

/* PDU handler interface (both client and server.) */
typedef ec_net_cbrc_t (*ec_pdu_handler_t)(uint8_t *, size_t, int,
        struct sockaddr_storage *, void *);

evutil_socket_t ec_net_bind_socket(struct sockaddr_storage *ss, int ss_len);

ssize_t ec_net_recvmsg(evutil_socket_t sd, uint8_t *b, size_t b_sz,
        int *flags, struct sockaddr *peer, socklen_t *peerlen);

void ec_net_pullup_all(evutil_socket_t sd, ec_pdu_handler_t pdu_proc, void *a);

ssize_t ec_net_pullup(evutil_socket_t sd, uint8_t *b, size_t b_sz,
        int *flags, struct sockaddr *peer, socklen_t *peerlen, int *e);

int ec_net_send(uint8_t h[EC_COAP_HDR_SIZE], uint8_t *o, size_t o_sz,
        uint8_t *p, size_t p_sz, evutil_socket_t sd,
        struct sockaddr_storage *d);

int ec_net_socklen(const struct sockaddr_storage *ss, uint8_t *ss_len);

#endif  /* !_EC_NET_H_ */
