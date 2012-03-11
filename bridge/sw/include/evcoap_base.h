#ifndef _EC_BASE_H_
#define _EC_BASE_H_

#include <u/libu.h>
#include <event2/event.h>
#include <event2/dns.h>

#include "evcoap_cli.h"
#include "evcoap_srv.h"

struct ec_s;
struct ec_dups_s;

typedef ec_cbrc_t (*ec_server_cb_t)(ec_server_t *, void *, struct timeval *, 
        bool);

/* An hosted resource. */
struct ec_rescb_s
{
    char *path;
    ec_server_cb_t cb;
    void *cb_args;
    TAILQ_ENTRY(ec_rescb_s) next;
};
typedef struct ec_rescb_s ec_rescb_t;

/* A listening CoAP endpoint. */
/* TODO Security context goes here. */
struct ec_listener_s
{
    evutil_socket_t sd;
    struct event *ev_input;

    TAILQ_ENTRY(ec_listener_s) next;
};
typedef struct ec_listener_s ec_listener_t;

struct ec_cached_pdu_s
{
    bool is_set;
    uint8_t hdr[4];
    uint8_t *opts;
    size_t opts_sz;
    uint8_t *payload;
    size_t payload_sz;
};
typedef struct ec_cached_pdu_s ec_cached_pdu_t;

/* Synoptic of last received PDUs, for duplicate detection. */
struct ec_recvd_pdu_s
{
    struct timeval when;
    struct sockaddr_storage who;
    uint16_t mid;
    ec_cached_pdu_t cached_pdu;
#define EC_DUP_LIFETIME     60  /* 1 minute seems reasonable. */
    struct event *countdown;
#define EC_DUP_KEY_MAX      256 /* Enough to hold "mid+IPaddr+port". */
    char key[EC_DUP_KEY_MAX];
    struct ec_dups_s *dups;
};
typedef struct ec_recvd_pdu_s ec_recvd_pdu_t;

struct ec_dups_s
{
    u_hmap_t *map;          /* Lookup key is MID + peer address. */
    struct ec_s *base;      /* Back pointer to the evcoap base. */
};
typedef struct ec_dups_s ec_dups_t;

struct ec_cfg_s
{
    bool block_is_stateless;
    uint8_t block_szx;
};
typedef struct ec_cfg_s ec_cfg_t;

struct ec_s
{
    /* Currently active client, server and observe transactions. */
    ec_servers_t servers;
    ec_clients_t clients;
    TAILQ_HEAD(, ec_observation_s) observing;

    /* Bound sockets. */
    TAILQ_HEAD(, ec_listener_s) listeners;

    /* Registered URI and associated callbacks. */
    TAILQ_HEAD(, ec_rescb_s) resources;

    /* Fallback in case incoming request does not match any resource. */
    ec_server_cb_t fb;
    void *fb_args;

    /* Duplicate handling subsystem. */
    ec_dups_t dups;

    /* Runtime configuration. */
    ec_cfg_t cfg;

    struct event_base *base;
    struct evdns_base *dns;
};
typedef struct ec_s ec_t;

int ec_listeners_add(ec_t *coap, evutil_socket_t sd);
ec_listener_t *ec_listener_new(ec_t *coap, evutil_socket_t sd);
void ec_listener_free(ec_listener_t *l);

/* Duplicate handling. */
int ec_dups_init(ec_t *coap, ec_dups_t *dups);
void ec_dups_term(ec_dups_t *dups);
int ec_dups_insert(ec_dups_t *dups, struct sockaddr_storage *ss,
        uint16_t mid);
int ec_dups_delete(ec_dups_t *dups, const char *key);
ec_recvd_pdu_t *ec_dups_search(ec_dups_t *dups, uint16_t mid,
        struct sockaddr_storage *peer);
int ec_dups_handle_incoming_srvmsg(ec_dups_t *dups, uint16_t mid, int sd,
        struct sockaddr_storage *ss);
int ec_dups_handle_incoming_climsg(ec_dups_t *dups, uint16_t mid, int sd,
        struct sockaddr_storage *ss);

ec_recvd_pdu_t *ec_recvd_pdu_new(const char *key, ec_t *coap, ec_dups_t *dups,
        struct sockaddr_storage *ss, uint16_t mid);
int ec_recvd_pdu_update(ec_recvd_pdu_t *recvd, uint8_t *hdr,
        uint8_t *opts, size_t opts_sz, uint8_t *payload,
        size_t payload_sz);
void ec_recvd_pdu_free(void *recvd_pdu);

/* Configuration handling. */
int ec_cfg_init(ec_cfg_t *cfg);
int ec_cfg_set_block_sz(ec_cfg_t *cfg, size_t val);
int ec_cfg_get_block_info(ec_cfg_t *cfg, bool *is_stateless, uint8_t *szx);

/* URI and associated callback. */
ec_rescb_t *ec_rescb_new(const char *url, ec_server_cb_t cb, void *args);
void ec_rescb_free(ec_rescb_t *r);

#endif  /* !_EC_BASE_H_ */
