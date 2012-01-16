#include <sys/time.h>
#include <u/libu.h>

#include "kache.h"

#define DEFAULT_MAX 50
#define HISTORY_SIZE 100

//TODO: use copy?

// int  u_hmap_opts_copy (u_hmap_opts_t *to, u_hmap_opts_t *from)
// http://www.koanlogic.com/libu/api/html/group__hmap.html
//



kache_t *kache_init()
{
    kache_t *kache;
    dbg_err_if((kache = u_zalloc(sizeof(kache_t))) == NULL);
    u_hmap_opts_t *opts;
    u_hmap_t *hmap = NULL;

    u_hmap_opts_new(&opts);

    dbg_err_if(u_hmap_opts_set_val_freefunc (opts, NULL));

    dbg_err_if (u_hmap_opts_set_val_type(opts,
                            U_HMAP_OPTS_DATATYPE_POINTER));
    dbg_err_if (u_hmap_opts_set_policy (opts, U_HMAP_PCY_LFU));
    dbg_err_if (u_hmap_opts_set_max (opts, DEFAULT_MAX));
    dbg_err_if (u_hmap_opts_unset_option(opts,U_HMAP_OPTS_NO_OVERWRITE));
    dbg_err_if(u_hmap_easy_new(opts, &hmap));

    kache->hmap = hmap;
    kache->hmap_opts = opts;
    TAILQ_INIT(&kache->history);
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
int kache_set_max_size(kache_t *kache, int max_size)
{
    dbg_err_if (u_hmap_opts_set_max (kache->hmap_opts, max_size));
    return 0;
err:
    return -1;
}


void kache_free_history(kache_t *kache)
{
    kache_request_t *item;
    while ((item = TAILQ_FIRST(&kache->history)) != NULL)
    {
        TAILQ_REMOVE(&kache->history, item, next);
        free(item->resource_key);
        free(item->tv);
        free(item);
    }
}

void kache_free(kache_t *kache)
{
    u_hmap_opts_free(kache->hmap_opts);
    u_hmap_easy_free(kache->hmap);
    kache_free_history(kache);
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
int kache_push_history(kache_t *kache, const char *key, const void *resource)
{
    kache_request_t *kache_request;
    dbg_err_if( (kache_request = malloc(sizeof(kache_request_t))) == NULL );

    struct timeval *tv;
    dbg_err_if( (tv = malloc(sizeof(struct timeval))) == NULL );
    dbg_err_if( gettimeofday(tv, NULL));
    kache_request->tv = tv;

    dbg_err_if( (kache_request->resource_key = malloc(strlen(key) + 1)) == NULL);
    dbg_err_if( strcpy(kache_request->resource_key,key) == NULL);

    kache_request->resource = resource;
    TAILQ_INSERT_HEAD(&kache->history, kache_request, next);
    return 0;
err:
    return -1;
}

void *kache_get(kache_t *kache, const char *key)
{
    //u_hmap_o_t *obj = u_zalloc(sizeof(u_hmap_o_t));
    //u_hmap_get (u_hmap_t *hmap, const void *key, &obj);
    void *resource = u_hmap_easy_get (kache->hmap, key);
    dbg_err_if(kache_push_history(kache,key,resource));
    return resource;
err:
    return NULL;
}

