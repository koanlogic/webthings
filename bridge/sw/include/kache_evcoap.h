#ifndef _KACHE_EVCOAP_H_
#define _KACHE_EVCOAP_H_
#include "kache.h"
#include "evcoap.h"

struct kache_evcoap_s
{
    kache_t *kache;
    struct event_base *base;
};
typedef struct kache_evcoap_s kache_evcoap_t;

struct kache_evcoap_data_s
{
    char *placeholder;
};
typedef struct kache_evcoap_data_s kache_evcoap_data_t;

kache_evcoap_t *kache_init_evcoap(kache_t *kache, struct event_base *base);
void kache_free_evcoap(kache_evcoap_t *ke);

kache_evcoap_data_t *kache_init_evcoap_data();
void kache_free_evcoap_data(kache_evcoap_data_t *data);

int kache_store_evcoap_response(kache_evcoap_t *ke, ec_client_t *cli);

void kache_evcoap_timer_cb(int i, short e,void *arg);

#endif /* _KACHE_EVCOAP_H_ */
