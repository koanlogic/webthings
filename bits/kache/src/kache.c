#include <sys/time.h>
#include <u/libu.h>

#include "kache.h"

#define MAX 50


//TODO: use copy?

// int  u_hmap_opts_copy (u_hmap_opts_t *to, u_hmap_opts_t *from)
// http://www.koanlogic.com/libu/api/html/group__hmap.html
//
typedef struct kache_request {
    struct timeval *tv; //request timestamp
    char *resource_key;
    void *kache_entry;
    TAILQ_ENTRY(kache_request) next;
} kache_request_t;

struct kache {
    u_hmap_t *hmap;
    u_hmap_opts_t *hmap_opts;
    //void (*k_free)(void *obj);
    TAILQ_HEAD(,kache_req_t) history;
};

kache_t *kache_init()
{
    kache_t *kache;
    dbg_err_if((kache = u_zalloc(sizeof(kache_t))) == NULL);
    u_hmap_opts_t *opts;
    u_hmap_t *hmap = NULL;

    u_hmap_opts_init(opts);

    dbg_err_if(u_hmap_easy_new(opts, &hmap));

    dbg_err_if (u_hmap_opts_set_val_type(opts,
                            U_HMAP_OPTS_DATATYPE_POINTER));
    //dbg_err_if (u_hmap_opts_set_key_type (opts, U_HMAP_OPTS_DATATYPE_STRING));
    //dbg_err_if (u_hmap_opts_set_policy (opts, U_HMAP_PCY_LFU));
    //dbg_err_if (u_hmap_opts_set_max (opts, MAX));
    u_hmap_opts_unset_option(opts,U_HMAP_OPTS_NO_OVERWRITE);
    kache->hmap = hmap;
    kache->hmap_opts = opts;
    return kache;

err:
    return NULL;
}
/*
*/


int kache_set_freefunc(kache_t *kache, void (*k_free)(void *obj))
{
    dbg_err_if(u_hmap_opts_set_val_freefunc (kache->hmap_opts, k_free));
    return 0;
err:
    return -1;
}

void kache_free(kache_t *kache)
{
    u_hmap_opts_free(kache->hmap_opts);
    u_hmap_easy_free(kache->hmap);
    free(kache);
}

int kache_set(kache_t *kache, const char *key, const void *content)
{
    //u_hmap_o_t *obj = u_hmap_o_new (kachehmap, key, content);
    //u_hmap_put (kache->hmap, u_hmap_o_t *obj, NULL);
    dbg_err_if(u_hmap_easy_put(kache->hmap,key, content));
    return 0;
err:
    return -1;
    
}
int kache_unset(kache_t *kache, const char *key)
{
    //u_hmap_del (u_hmap_t *hmap, const void *key, NULL);
    dbg_err_if(u_hmap_easy_del (kache->hmap, key));
    return 0;
err:
    return -1;

}
void *kache_get(kache_t *kache, const char *key)
{
    //u_hmap_o_t *obj = u_zalloc(sizeof(u_hmap_o_t));
    //u_hmap_get (u_hmap_t *hmap, const void *key, &obj);
    void *obj = u_hmap_easy_get (kache->hmap, key);
    return obj;
}

