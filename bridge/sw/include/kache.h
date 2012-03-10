#ifndef _KACHE_H_
#define _KACHE_H_
#include <sys/queue.h>

typedef struct kache_entry kache_entry_t;
typedef struct kache_history_record kache_history_record_t;


typedef struct kache {
    u_hmap_t *hmap;
    u_hmap_opts_t *hmap_opts;
    int history_length;
    //TAILQ_HEAD(,kache_request) history;
    void (*k_free)(void *obj);
    void (*set_procedure)(kache_entry_t *entry,void *arg);
    void *set_procedure_arg;

} kache_t;

struct kache_entry {
    void *resource;
    int access_counter;
    struct timeval *insert_time;
    kache_t *kache;
    int history_size;
    kache_history_record_t **history;
    //TAILQ_HEAD(kache_history_record_h,kache_history_record) history;

};

struct kache_history_record {
    struct timeval *insert_time; //request timestamp
    int access_counter;
    TAILQ_ENTRY(kache_history_record) next;
};

/*typedef struct kache_request {
    struct timeval *tv; //request timestamp
    char *resource_key;
    const void *resource;
    TAILQ_ENTRY(kache_request) next;
} kache_request_t;*/

kache_t *kache_init();
int kache_init_data_structure(kache_t *kache);

int kache_set_freefunc(kache_t *kache, void (*k_free)(void *obj));
int kache_set_max_size(kache_t *kache, int max_size);
void kache_free(kache_t *kache);

int kache_set(kache_t *kache, const char *key, const void *content);
int kache_set_expire(kache_t *kache, const char *key, const void *content, int expire_sec);
int kache_unset(kache_t *kache, const char *key);
void *kache_get(kache_t *kache, const char *key);

int kache_attach_set_procedure(kache_t *kache, 
                void (*procedure)(kache_entry_t *entry,void *arg), 
                void *arg);

int kache_set_custom_discard_policy(kache_t *kache, int (*compare)(void *o1, void *o2));

//int kache_foreach_arg(kache_t *kache, int f(const void *kache_entry, const void *arg), const void *arg);

int kache_set_history_length(kache_t *kache, int history_length);
#endif

