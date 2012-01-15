#ifndef _KACHE_H_
#define _KACHE_H_


#define KACHE_HISTORY_FOREACH(req,kache)         \
          TAILQ_FOREACH(req,kache->history,next)

typedef struct kache kache_t;

kache_t *kache_init();

int kache_set_freefunc(kache_t *kache, void (*k_free)(void *obj));
void kache_free(kache_t *kache);

int kache_set(kache_t *kache, const char *key, const void *content);
int kache_unset(kache_t *kache, const char *key);
void *kache_get(kache_t *kache, const char *key);

#endif

