#include <sys/time.h>

#include "kache.h"

#define DEFAULT_MAX 50
#define HISTORY_SIZE 100
#define DEFAULT_EXPIRATION_TIME 100
#define DEFAULT_HISTORY_LEN 5
//TODO discard policy

kache_t *kache_init()
{
    kache_t *kache;
    dbg_err_if((kache = u_zalloc(sizeof(kache_t))) == NULL);
    u_hmap_opts_t *opts;
    u_hmap_opts_new(&opts);
    dbg_err_if (u_hmap_opts_set_val_type(opts,
                            U_HMAP_OPTS_DATATYPE_POINTER));
    dbg_err_if (u_hmap_opts_set_policy (opts, U_HMAP_PCY_LFU));
    dbg_err_if (u_hmap_opts_set_max (opts, DEFAULT_MAX));
    dbg_err_if (u_hmap_opts_unset_option(opts,U_HMAP_OPTS_NO_OVERWRITE));
    dbg_err_if (u_hmap_opts_unset_option(opts,U_HMAP_OPTS_OWNSDATA));

    kache->hmap = NULL;
    kache->hmap_opts = opts;
    kache->set_procedure = NULL;
    kache->set_procedure_arg = NULL;

    return kache;

err:
    return NULL;
}

int kache_init_data_structure(kache_t *kache)
{
    u_hmap_t *hmap = NULL;
    dbg_err_if(u_hmap_new(kache->hmap_opts, &hmap));
    kache->hmap = hmap;
    return 0;
err:
    return -1;
}


int kache_set_max_size(kache_t *kache, int max_size)
{
    dbg_err_if (u_hmap_opts_set_size (kache->hmap_opts, max_size));
    dbg_err_if (u_hmap_opts_set_max (kache->hmap_opts, max_size));
    return 0;
err:
    return -1;
}

void kache_set_free_obj_func(kache_t *kache,void (*free_obj)(kache_obj_t *obj))
{
    kache->free_obj = free_obj;
}

void kache_default_free_func(kache_obj_t *obj)
{
    kache_rep_foreach(obj,kache_free_kache_rep);
    kache_free_kache_obj(obj);
}

/*
 * Free the entire cache
 * uses free_obj if set, kache_free_kache_obj otherwise
 */
void kache_free(kache_t *kache)
{
    if(kache->free_obj)
        kache->free_obj;
    else
        u_hmap_foreach(kache->hmap,kache_default_free_func);

    u_hmap_free(kache->hmap);
    u_hmap_opts_free(kache->hmap_opts);
    u_free(kache);
}


/* Adds a kache_obj to kache
 * Returns 0 on success, -1 on failure
 * If an object with the same key already exists in kache
 * kache_obj will point to that object
 */

int kache_set(kache_t *kache, 
        const char *key, 
        kache_obj_t *obj, 
        kache_obj_t **overwrite)
{
    u_hmap_o_t *tmp;

    //object already in, update history
    if(u_hmap_get(kache->hmap,key,&tmp) == U_HMAP_ERR_NONE)
        if(overwrite)
            *overwrite = (kache_obj_t*) u_hmap_o_get_val(tmp);
    u_hmap_o_t *hobj;
    dbg_err_if( (hobj = u_hmap_o_new (kache->hmap, key, obj)) == NULL);
    dbg_err_if( u_hmap_put (kache->hmap, hobj, &tmp));
    u_hmap_o_free(tmp);
    if(kache->set_procedure != NULL)
        kache->set_procedure(obj,kache->set_procedure_arg);
    return 0;
err:
    return -1;
}

/*
 * Unsets cache object
 * Returns 0 on success, -1 on failure
 * Stores a pointer to the deleted object in deleted_obj
 */
int kache_unset(kache_t *kache, const char *key, kache_obj_t **deleted_obj)
{
    u_hmap_o_t *obj;
    dbg_err_if(u_hmap_del (kache->hmap, key, &obj));
    if(deleted_obj)
        *deleted_obj = u_hmap_o_get_val(obj);
    u_hmap_o_free(obj);
    return 0;
err:
    return -1;
}

kache_obj_t *kache_get(kache_t *kache, const char *key)
{
    u_hmap_o_t *obj;
    u_hmap_get (kache->hmap, key, &obj);
    if (obj == NULL)
        return NULL;
    return (kache_obj_t*) u_hmap_o_get_val(obj);
err:
    return NULL;
}
int kache_attach_set_procedure(kache_t *kache, 
                void (*procedure)(kache_obj_t *entry,void *arg), 
                void *arg)
{
    kache->set_procedure = procedure;
    kache->set_procedure_arg = arg;
    return 0;
}
/*
 * Sets a custom discard policy for the hmap
 */

int kache_set_custom_discard_policy(kache_t *kache, int (*compare)(void *o1, void *o2))
{
    dbg_err_if (u_hmap_opts_set_policy(kache->hmap_opts, U_HMAP_PCY_CUSTOM)); 
    dbg_err_if (u_hmap_opts_set_policy_cmp(kache->hmap_opts, compare));
    return 0;
err:
    return -1;
}
