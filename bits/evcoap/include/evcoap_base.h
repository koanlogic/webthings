#ifndef _EC_BASE_H_
#define _EC_BASE_H_

#include <event2/event.h>
#include <event2/dns.h>

#include "evcoap_cli.h"
#include "evcoap_srv.h"

struct ec_s;

typedef int (*ec_server_cb_t)(struct ec_s *, ec_server_t *, void *, bool,
        struct timeval *);

typedef int (*ec_catchall_cb_t)(struct ec_s *, ec_server_t *, void *);

/* An hosted resource. */
struct ec_resource_s
{
    const char *path;
    ec_server_cb_t cb;
    void *cb_args;
    /* TODO busy flag + resched timer */
    TAILQ_ENTRY(ec_resource_s) next;
};

/* A listening CoAP endpoint. */
struct ec_listener_s
{
    evutil_socket_t sd;
    /* Security context goes here. */
    struct event *req_event;
    TAILQ_ENTRY(ec_listener_s) next;
};

/* Synoptic of last received PDUs, for duplicate detection. */
struct ec_recvd_pdu_s
{
    struct timeval when;
    struct sockaddr_storage who;
    ev_socklen_t who_len;
    /* TODO what, i.e. cached response */
    ev_uint16_t mid;
    TAILQ_ENTRY(ec_recvd_pdu_s) next;
};

typedef struct ec_s
{
    /* Currently active client and server transactions. */
    TAILQ_HEAD(, ec_client_s) clients;
    TAILQ_HEAD(, ec_server_s) servers;

    /* Bound sockets. */
    TAILQ_HEAD(, ec_listener_s) listeners;

    /* Registered URI and associated callbacks. */
    TAILQ_HEAD(, ec_resource_s) resources;

    /* Fallback in case incoming request does not match any resource. */
    ec_catchall_cb_t fb;
    void *fb_args;

    /* Duplicate handling. */
    TAILQ_HEAD(, ec_recvd_pdu_s) window;

    struct event_base *base;
    struct evdns_base *dns;
} ec_t;

#endif  /* !_EC_BASE_H_ */
