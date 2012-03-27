
#ifndef _KACHE_HISTORY_H_
#define _KACHE_HISTORY_H_
struct kache_history_record_s 
{
    struct timeval *insert_time; //request timestamp
    int access_counter;
    TAILQ_ENTRY(kache_history_record) next;
};

typedef struct kache_history_record_s kache_history_record_t;

int kache_history_add_record(kache_history_record_t **history, int max_length, kache_history_record_t);

void kache_free_history_record(kache_history_record_t *record);
void kache_free_history(kache_history_record_t **history)
kache_history_record_t *kache_init_history_record();
int kache_push_history_record(kache_history_record_t **history,
                                 kache_history_record_t *record,
                                 int *curr_size,
                                 int max_size);


#endif /* _KACHE_HISTORY_H_ */
