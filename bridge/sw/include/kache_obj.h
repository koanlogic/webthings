#ifndef _KACHE_PDU_H_
#define _KACHE_PDU_H_

#include <sys/queue.h>
#include <event2/event.h>

// Lookup on response code and method?

typedef enum
{
    COAP,
    HTTP
} kache_protocol_type_t;

typedef enum
{
    KACHE_TEXT,
    KACHE_APPLICATION
} kache_media_type_t;

typedef enum
{
    KACHE_XML,
    KACHE_OCTET_STREAM,
    KACHE_EXI,
    KACHE_JSON,
    KACHE_LINK_FORMAT,
    KACHE_PLAIN
    
} kache_media_subtype_t;

struct kache_content_type_s
{
    kache_media_type_t type;
    kache_media_subtype_t subtype;
};
typedef struct kache_content_type_s kache_content_type_t;

struct kache_keyval_s 
{
    char *key;
    size_t key_sz;
    char *value;
    size_t value_sz;
    TAILQ_ENTRY(kache_keyval_s) next;
};

typedef struct kache_keyval_s kache_keyval_t;


struct kache_rep_s 
{
    TAILQ_HEAD(,  kache_keyval_s) keyvalq;
    char *payload;
    size_t payload_size;
    char *ETag;
    kache_content_type_t *media_type;
    struct timeval *ts;
    unsigned int max_age;
    void *per_protocol_data;
    struct event *timer;
    TAILQ_ENTRY(kache_rep_s) next;
};
typedef struct kache_obj_s kache_obj_t;

struct kache_obj_s
{
    kache_protocol_type_t protocol_type;
    char *key;
    TAILQ_HEAD(, kache_rep_s) reps;
};

typedef struct kache_rep_s kache_rep_t;

kache_obj_t *kache_init_kache_obj();
kache_rep_t *kache_init_kache_rep();

int kache_add_key_val_no_sz(kache_rep_t *rep, char *key, char *val);
int kache_add_key_val(kache_rep_t *rep, char *key,size_t key_sz, char *val, size_t val_sz);

int kache_add_rep(kache_obj_t *obj, kache_rep_t *rep);
int kache_remove_rep(kache_obj_t *obj, kache_rep_t *rep);
kache_rep_t *kache_peak_rep(kache_obj_t *obj);
kache_rep_t *kache_get_rep(kache_obj_t *obj, int index);
void kache_clear_kache_rep(kache_rep_t *rep);

int kache_rep_foreach(kache_obj_t *obj, int (*f)(kache_rep_t *rep));

void kache_free_kache_keyvalq(kache_rep_t *rep);
void kache_free_kache_keyval(kache_keyval_t *keyval);
void kache_free_kache_obj(kache_obj_t *obj);
int kache_free_kache_rep_with_data(kache_rep_t *rep, void **data);
int kache_free_kache_rep(kache_rep_t *rep);
kache_rep_t *kache_get_rep_by_media_type(kache_obj_t *obj, kache_content_type_t *media_type);


int kache_set_rep_timer(struct event_base *base, 
                kache_rep_t *rep, 
                int seconds, 
                void (*cb)(int i, short e,void *arg),
                void *arg);

#endif /* _KACHE_PDU_H_ */
