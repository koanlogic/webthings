#ifndef _KACHE_H_
#define _KACHE_H_
#include <sys/queue.h>

#define KACHE_HISTORY_FOREACH(req,kache)         \
          TAILQ_FOREACH(req,&kache->history,next)

typedef struct kache {
    u_hmap_t *hmap;
    u_hmap_opts_t *hmap_opts;
    TAILQ_HEAD(,kache_request) history;
   //void (*k_free)(void *obj);
} kache_t;

typedef struct kache_request {
    struct timeval *tv; //request timestamp
    char *resource_key;
    const void *resource;
    TAILQ_ENTRY(kache_request) next;
} kache_request_t;

kache_t *kache_init();

int kache_set_freefunc(kache_t *kache, void (*k_free)(void *obj));
int kache_set_max_size(kache_t *kache, int max_size);
void kache_free(kache_t *kache);

int kache_set(kache_t *kache, const char *key, const void *content);
int kache_unset(kache_t *kache, const char *key);
void *kache_get(kache_t *kache, const char *key);

#endif

