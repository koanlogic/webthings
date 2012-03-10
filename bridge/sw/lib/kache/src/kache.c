#include <sys/time.h>
#include <u/libu.h>

#include "kache.h"

#define DEFAULT_MAX 50
#define HISTORY_SIZE 100
#define DEFAULT_EXPIRATION_TIME 100
#define DEFAULT_HISTORY_LEN 5

//TODO add errors in case the hmap in NULL
//TODO remove NULL control in free history
//TODO line 625
// if (hmap->opts->options & U_HMAP_OPTS_OWNSDATA)
// segfault if kay is not allocated dynamically
// TODO leak on history record
void kache_free_kache_entry(void *obj);
void kache_free_kache_entry_history(kache_entry_t *kache_entry);

kache_t *kache_init()
{
    kache_t *kache;
    dbg_err_if((kache = u_zalloc(sizeof(kache_t))) == NULL);
    u_hmap_opts_t *opts;
    
    

    u_hmap_opts_new(&opts);

    dbg_err_if(u_hmap_opts_set_val_freefunc (opts, kache_free_kache_entry));

    dbg_err_if (u_hmap_opts_set_val_type(opts,
                            U_HMAP_OPTS_DATATYPE_POINTER));
    dbg_err_if (u_hmap_opts_set_policy (opts, U_HMAP_PCY_LFU));
    dbg_err_if (u_hmap_opts_set_max (opts, DEFAULT_MAX));
    dbg_err_if (u_hmap_opts_unset_option(opts,U_HMAP_OPTS_NO_OVERWRITE));
    dbg_err_if (u_hmap_opts_unset_option(opts,U_HMAP_OPTS_OWNSDATA));

    kache->hmap = NULL;
    kache->hmap_opts = opts;
    kache->history_length = DEFAULT_HISTORY_LEN;
    kache->k_free = NULL;
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

/*
*/

int kache_set_custom_discard_policy(kache_t *kache, int (*compare)(void *o1, void *o2))
{
    dbg_err_if (u_hmap_opts_set_policy(kache->hmap_opts, U_HMAP_PCY_CUSTOM)); 
    dbg_err_if (u_hmap_opts_set_policy_cmp(kache->hmap_opts, compare));
    return 0;
err:
    return -1;
}
void kache_free_kache_entry(void *obj)
{
    kache_entry_t *k_obj = (kache_entry_t*)obj;

    if(k_obj->kache->k_free == NULL)
    {
        u_free(k_obj->resource);
    }
    else
        k_obj->kache->k_free(k_obj->resource);
    kache_free_kache_entry_history(k_obj);
    u_free(k_obj->insert_time);
    u_free(k_obj);
}

int kache_set_freefunc(kache_t *kache, void (*k_free)(void *obj))
{
    kache->k_free = k_free;
    dbg_err_if(u_hmap_opts_set_val_freefunc (kache->hmap_opts, kache_free_kache_entry ));
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

int kache_set_history_length(kache_t *kache, int history_length)
{
    kache->history_length = history_length;
    return 0;
}
void kache_free_history_record(kache_history_record_t *record)
{
    if(record == NULL)
        return;
    u_free(record->insert_time);
    u_free(record);
}
void kache_free_kache_entry_history(kache_entry_t *kache_entry)
{

    int i;

    for(i=0;i<kache_entry->history_size;i++)
    {
        kache_free_history_record(kache_entry->history[i]);
    }
    u_free(kache_entry->history);
    /*
    kache_history_record_t *item;
    while ((item = TAILQ_FIRST(&kache_entry->history)) != NULL)
    {
        TAILQ_REMOVE(&kache_entry->history, item, next);
        kache_free_history_record(item);
    }*/
}

void kache_free(kache_t *kache)
{
    u_hmap_opts_set_option(kache->hmap_opts,U_HMAP_OPTS_OWNSDATA);
    u_hmap_free(kache->hmap);
    u_hmap_opts_free(kache->hmap_opts);
    u_free(kache);
}

kache_entry_t *kache_init_kache_entry(kache_t *kache)
{
    kache_entry_t *kache_entry; 
    dbg_err_if((kache_entry = u_zalloc(sizeof(kache_entry_t))) == NULL);
    kache_entry->resource = NULL;
    kache_entry->access_counter = 0;
    kache_entry->history_size = 0;
    kache_entry->kache = kache;
    dbg_err_if( (kache_entry->insert_time = u_zalloc(sizeof(struct timeval))) == NULL);

    //TAILQ_INIT(&kache_entry->history);
    //u_calloc(kache->history_length, sizeof(kache_history_record_t));
    dbg_err_if( (kache_entry->history = \
            u_zalloc( sizeof(void*) * kache->history_length)) == NULL);
    return kache_entry;
err:
    return NULL;
}


kache_history_record_t *kache_init_history_record()
{
    kache_history_record_t *record;
    dbg_err_if( (record = u_zalloc(sizeof(kache_history_record_t))) == NULL);
    //dbg_err_if( (record->insert_time = u_zalloc(sizeof(struct timeval))) == NULL);
    return record;
err:
    return NULL;

}
int kache_history_pop_last(kache_entry_t *entry)
{
    /*kache_history_record_t *last;
    dbg_err_if (entry == NULL);
    dbg_err_if ((last = TAILQ_LAST(&entry->history, kache_history_record_h))  == NULL);
    TAILQ_REMOVE(&entry->history, last, next);
    kache_free_history_record(last);
    */
    kache_free_history_record(entry->history[entry->kache->history_length - 1]);
    return 0;
//err:
//    return -1;

}
int kache_push_history_record(kache_entry_t *kache_entry,
                              kache_history_record_t *record)
{
    //max size of history reached, remove tail element
    if(kache_entry->history_size + 1 > kache_entry->kache->history_length)
        dbg_err_if(kache_history_pop_last(kache_entry));
    else
        kache_entry->history_size = kache_entry->history_size + 1;
    int i;
    for(i = kache_entry->history_size; i!=0; i--)
        kache_entry->history[i] = kache_entry->history[i-1];
    kache_entry->history[0] = record;
    return 0;
err:
    return -1;

}

/* key is copied, must be freed by user
 *
 */

int kache_set(kache_t *kache, const char *key, const void *content)
{
    char *newkey = malloc(strlen(key)+1);
    dbg_err_if(strcpy(newkey,key)==NULL);
    kache_entry_t *kache_entry;
    u_hmap_o_t *tmp;
    unsigned int overwrite = 0;
    //object already in, update history
    if(u_hmap_get(kache->hmap,newkey,&tmp) == U_HMAP_ERR_NONE)
    {
        overwrite = 1;
        kache_entry = (kache_entry_t*) u_hmap_o_get_val(tmp);
        kache_history_record_t *record;
        dbg_err_if( (record = kache_init_history_record()) == NULL);
        record->insert_time = kache_entry->insert_time;
        record->access_counter = kache_entry->access_counter;
        kache_push_history_record(kache_entry,record);
        dbg_err_if( (kache_entry->insert_time = u_zalloc(sizeof(struct timeval))) == NULL);
        kache_entry->access_counter = 0;
    }
    else
        dbg_err_if( (kache_entry = kache_init_kache_entry(kache)) == NULL);
    dbg_err_if( gettimeofday(kache_entry->insert_time,NULL));
    void *tmpres = kache_entry->resource;
    kache_entry->resource = (void*)content;
    u_hmap_o_t *obj;
    dbg_err_if( (obj = u_hmap_o_new (kache->hmap, newkey, kache_entry)) == NULL);
    dbg_err_if( u_hmap_put (kache->hmap, obj, &tmp));
    if( tmp != NULL )
    {   //free old resource (in case of overwrite)
        if(tmpres != kache_entry->resource)
        {//to avoid free when overwriting the same value
            if(kache->k_free!=NULL)
                kache->k_free(tmpres);
            else
                free(tmpres);
        }
        // if tmp is an entry popped because 
        // cache is full, free kache entry
        if(overwrite==0)
        {
            kache_free_kache_entry(u_hmap_o_get_val(tmp));
        }
        u_free(u_hmap_o_get_key(tmp));
        u_hmap_o_free(tmp);//free hmap object
    }
    if(kache->set_procedure != NULL)
        kache->set_procedure(kache_entry,kache->set_procedure_arg);
    return 0;
err:
    return -1;
}
int kache_unset(kache_t *kache, const char *key)
{
    u_hmap_o_t *obj;
    dbg_err_if(u_hmap_del (kache->hmap, key, &obj));
    kache_free_kache_entry(u_hmap_o_get_val(obj));
    u_free(u_hmap_o_get_key(obj));
    u_hmap_o_free(obj);

    return 0;
err:
    return -1;

}

void *kache_get(kache_t *kache, const char *key)
{
    u_hmap_o_t *obj;
    u_hmap_get (kache->hmap, key, &obj);
    if (obj == NULL)
        return NULL;
    kache_entry_t *tmp = ((kache_entry_t*) u_hmap_o_get_val(obj));
    tmp->access_counter = tmp->access_counter + 1;
    return tmp->resource;
err:
    return NULL;
}
/*
int kache_foreach_arg(kache_t *kache, 
        int f(const void *kache_entry, const void *arg), const void *arg)
{
       dbg_err_if (kache == NULL);
       dbg_err_if (f == NULL);
       dbg_err_if (u_hmap_foreach_arg (kache->hmap,f, arg));
       return 0;
err:
       return -1;
}
*/

int kache_attach_set_procedure(kache_t *kache, 
                void (*procedure)(kache_entry_t *entry,void *arg), 
                void *arg)
{
    kache->set_procedure = procedure;
    kache->set_procedure_arg = arg;
    return 0;
}
