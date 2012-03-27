#ifndef _KACHE_H_
#define _KACHE_H_

#include <sys/queue.h>
#include "u/libu.h"
#include "kache_obj.h"


typedef struct kache 
{
    u_hmap_t *hmap;
    u_hmap_opts_t *hmap_opts;
    void (*set_procedure)(kache_obj_t *obj, void *arg);
    void *set_procedure_arg;
    void (*free_obj)(kache_obj_t *obj);

} kache_t;



kache_t *kache_init();
int kache_init_data_structure(kache_t *kache);
void kache_set_free_obj_func(kache_t *kache,void (*free_obj)(kache_obj_t *obj));

int kache_set_freefunc(kache_t *kache, void (*k_free)(void *obj));
int kache_set_max_size(kache_t *kache, int max_size);
void kache_free(kache_t *kache);

int kache_set(kache_t *kache, 
                const char *key,
                kache_obj_t *obj, 
                kache_obj_t **overwrite);

int kache_unset(kache_t *kache, const char *key, kache_obj_t **deleted_obj);
kache_obj_t *kache_get(kache_t *kache, const char *key);

int kache_attach_set_procedure(kache_t *kache, 
                void (*procedure)(kache_obj_t *entry,void *arg), 
                void *arg);

int kache_set_custom_discard_policy(kache_t *kache, int (*compare)(void *o1, void *o2));


#endif /* _KACHE_H_   */

