#ifndef _KACHE_EVHTTP_H_
#define _KACHE_EVHTTP_H_
#include "kache.h"

struct kache_evhttp_s
{
    kache_t *kache;

}
typedef struct kache_evhttp_s kache_evhttp_t;


kache_evhttp_t *kache_init_kache_evhttp();


#endif /* _KACHE_EVHTTP_H_ */
