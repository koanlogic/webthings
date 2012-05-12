#include <u/libu.h>
#include "kache_obj.h"

void kache_clear_kache_rep(kache_rep_t *rep);

/*
 * Copies key and val into a kache_keyval_t instance
 * and adds it to the keyval queue of the representation
 *
 * TODO: PROBLEM: Should i copy?
 *
 */

int kache_add_key_val_no_sz(kache_rep_t *rep, char *key, char *val)
{
    return kache_add_key_val(rep,key,strlen(key),val,strlen(val));
}
int kache_add_key_val(kache_rep_t *rep, char *key, size_t key_sz, char *val, size_t val_sz)
{
    kache_keyval_t *keyval;
    dbg_err_if((keyval = u_zalloc(sizeof(kache_keyval_t))) == NULL);
    dbg_err_if((keyval->key = malloc(strlen(key)+1)) == NULL);
    dbg_err_if((keyval->value = malloc(strlen(val)+1)) == NULL);
    dbg_err_if(strncpy(keyval->key, key,key_sz) == NULL);
    keyval->key[key_sz] = '\0';
    dbg_err_if(strncpy(keyval->value, val,val_sz) == NULL);
    keyval->value[val_sz] = '\0';
    TAILQ_INSERT_TAIL(&rep->keyvalq, keyval, next);
    return 0;
err:
    return -1;
}

int kache_add_rep(kache_obj_t *obj, kache_rep_t *rep)
{
    TAILQ_INSERT_TAIL(&obj->reps, rep, next);
    return 0;
}
int kache_remove_rep(kache_obj_t *obj, kache_rep_t *rep)
{
    TAILQ_REMOVE(&obj->reps,rep,next);
    return 0;
}

kache_obj_t *kache_init_kache_obj()
{
    kache_obj_t *obj;
    dbg_err_if((obj = u_zalloc(sizeof(kache_obj_t)))==NULL);
    TAILQ_INIT(&obj->reps);
    return obj;
err:
    return NULL;
}

kache_rep_t *kache_init_kache_rep()
{
    kache_rep_t *rep;
    dbg_err_if((rep = u_zalloc(sizeof(kache_rep_t)))==NULL);

    TAILQ_INIT(&rep->keyvalq);
    return rep;
err:
    return NULL;
}

kache_rep_t *kache_peak_rep(kache_obj_t *obj)
{
    return TAILQ_FIRST(&obj->reps);
}

kache_rep_t *kache_get_rep_nth(kache_obj_t *obj, int index)
{
    kache_rep_t *rep;
    TAILQ_FOREACH(rep, &obj->reps, next)
    {
        if (index == 0)
            return rep;
        --index;
    }
    return NULL;
}

int kache_rep_foreach(kache_obj_t *obj, int (*f)(kache_rep_t *rep))
{
    kache_rep_t *rep;
    TAILQ_FOREACH(rep, &obj->reps, next)
    {
        dbg_err_if(f(rep));
    }
    return 0;
err:
    return -1;

}

kache_rep_t *kache_get_rep_by_media_type(kache_obj_t *obj, kache_content_type_t *media_type)
{
    kache_rep_t *rep;
    TAILQ_FOREACH(rep, &obj->reps, next)
    {
        if(rep->media_type->type == media_type->type &&
            rep->media_type->subtype == media_type->subtype)
            return rep;
    }
    return NULL;
}


void kache_free_kache_keyval(kache_keyval_t *keyval)
{
    if(keyval)
    {
        u_free(keyval->key);
        u_free(keyval->value);
        u_free(keyval);
    }
}
void kache_free_kache_keyvalq(kache_rep_t *rep)
{
        kache_keyval_t *keyval;
        while ((keyval = TAILQ_FIRST(&rep->keyvalq)))
        {
            TAILQ_REMOVE(&rep->keyvalq, keyval, next);
            kache_free_kache_keyval(keyval);
        }
}

void kache_free_kache_rep_with_data(kache_rep_t *rep, void **data)
{
    if(rep)
    {
        kache_clear_kache_rep(rep);
        if(data == NULL)
            u_free(rep->per_protocol_data);
        else
            *data = rep->per_protocol_data;
        u_free(rep);
    }
}


/*
 * Clears the representation, so that it can be overwritten
 * or freed
 */
void kache_clear_kache_rep(kache_rep_t *rep)
{
    if(rep)
    {
        if(rep->payload) 
            u_free(rep->payload);
        if(rep->ETag)
            u_free(rep->ETag);
        kache_free_kache_keyvalq(rep);
        u_free(rep->ts);
    } 
}

void kache_free_kache_rep(kache_rep_t *rep)
{
    kache_free_kache_rep_with_data(rep,NULL);
}


/*
 * Free a kache obj
 *
 */
void kache_free_kache_obj(kache_obj_t *obj)
{
    if(obj)
    {
        /*
        kache_rep_t *rep;
        while ((rep = TAILQ_FIRST(&obj->reps)))
        {
            TAILQ_REMOVE(&obj->reps, rep, next);
            if(free_data)
            {
                void **data;
                kache_free_kache_rep(rep,data);
                free_data(*data);
            }
            else
                kache_free_kache_rep(rep,NULL);
                
        }
        */
        u_free(obj->key);
        u_free(obj);
    }
}

int kache_set_rep_timer(struct event_base *base, 
        kache_rep_t *rep, 
        int seconds, 
        void (*cb)(int i, short e,void *arg),
        void *arg
        )
{
    dbg_err_if(base == NULL);
    dbg_err_if(rep == NULL);

    struct event *ev;
    if(rep->timer)
    {
        ev = rep->timer;
    }
    else
    {
        ev = evtimer_new(base,cb,arg);
        rep->timer = ev;
    }
    struct timeval *tv; 
    tv = malloc(sizeof(struct timeval));
    timerclear(tv);
    //TODO: bug:
    tv->tv_sec=seconds;
    evtimer_add(ev,tv);
    return 0;
err:
    return -1;

}

