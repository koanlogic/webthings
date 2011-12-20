#ifndef _EC_BASE_H_
#define _EC_BASE_H_

#include <event2/event.h>
#include <event2/dns.h>

#include "evcoap_txn.h"

typedef struct
{
    TAILQ_HEAD(, ec_client_s) clients;
    TAILQ_HEAD(, ec_server_s) servers;

    struct event_base *base;
    struct evdns_base *dns;
} ec_t;

#endif  /* !_EC_BASE_H_ */
