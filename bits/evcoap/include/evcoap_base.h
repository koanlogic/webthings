#ifndef _EC_BASE_H_
#define _EC_BASE_H_

#include <u/libu.h>
#include <event2/event.h>
#include <event2/dns.h>

#include "evcoap_cli.h"
#include "evcoap_srv.h"

struct ec_s;

typedef ec_cbrc_t (*ec_server_cb_t)(ec_server_t *, void *, struct timeval *, 
        bool);

/* An hosted resource. */
struct ec_resource_s
{
    char *path;
    ec_server_cb_t cb;
    void *cb_args;
    /* TODO busy flag + resched timer */
    TAILQ_ENTRY(ec_resource_s) next;
};
typedef struct ec_resource_s ec_resource_t;

/* A listening CoAP endpoint. */
struct ec_listener_s
{
    evutil_socket_t sd;
    /* TODO Security context goes here. */
    struct event *ev_input;

    TAILQ_ENTRY(ec_listener_s) next;
};
typedef struct ec_listener_s ec_listener_t;

struct ec_cached_pdu_s
{
    ev_uint8_t hdr[4];
    ev_uint8_t *opts;
    size_t opts_sz;
    ev_uint8_t *payload;
    size_t payload_sz;
};
typedef struct ec_cached_pdu_s ec_cached_pdu_t;

/* Synoptic of last received PDUs, for duplicate detection. */
struct ec_recvd_pdu_s
{
    struct timeval when;
    struct sockaddr_storage who;
    ev_socklen_t who_len;
    ev_uint16_t mid;
    ec_cached_pdu_t cached_pdu;
};
typedef struct ec_recvd_pdu_s ec_recvd_pdu_t;

struct ec_dups_s
{
#define EC_DUP_KEY_MAX          256 /* mid'-'IPaddr'-'port */
    u_hmap_t *map;  /* Lookup key is MID + peer address. */

#define EC_DUP_CHORES_INTERVAL  20  /* Cleanup every 20 seconds. */
    struct event *chores_timer;
};
typedef struct ec_dups_s ec_dups_t;

struct ec_s
{
    /* Currently active client and server transactions. */
    TAILQ_HEAD(, ec_client_s) clients;
    TAILQ_HEAD(, ec_server_s) servers;

    /* Bound sockets. */
    TAILQ_HEAD(, ec_listener_s) listeners;

    /* Registered URI and associated callbacks. */
    TAILQ_HEAD(, ec_resource_s) resources;

    /* Fallback in case incoming request does not match any resource. */
    ec_server_cb_t fb;
    void *fb_args;

    /* Duplicate handling. */
    ec_dups_t dups;

    struct event_base *base;
    struct evdns_base *dns;
};
typedef struct ec_s ec_t;

int ec_listeners_add(ec_t *coap, evutil_socket_t sd);
ec_listener_t *ec_listener_new(ec_t *coap, evutil_socket_t sd);
void ec_listener_free(ec_listener_t *l);

/* Duplicate handling. */
int ec_dups_init(ec_t *coap, ec_dups_t *dups);
int ec_dups_insert(ec_dups_t *dups, ec_recvd_pdu_t *recvd);
ec_recvd_pdu_t *ec_dups_search(ec_dups_t *dups, ev_uint8_t mid,
        struct sockaddr_storage *peer);

void ec_recvd_pdu_free(void *recvd_pdu);


#endif  /* !_EC_BASE_H_ */
