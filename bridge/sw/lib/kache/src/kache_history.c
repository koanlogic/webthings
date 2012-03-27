#include "kache_history.h"

kache_history_record_t *kache_init_history_record()
{
    kache_history_record_t *record;
    dbg_err_if( (record = u_zalloc(sizeof(kache_history_record_t))) == NULL);
    return record;
err:
    return NULL;

}

void kache_free_history_record(kache_history_record_t *record)
{
    if(record == NULL)
        return;
    u_free(record->insert_time);
    u_free(record);
}

void kache_free_history(kache_history_record_t **history, int curr_size)
{

    int i;

    for(i=0;i<kache_entry->history_size;i++)
    {
        kache_free_history_record(kache_entry->history[i]);
    }
    u_free(kache_entry->history);
}

int kache_history_pop_last(kache_history_record_t **history,
                            int max_size)
{
    kache_free_history_record(history[max_size - 1]);
    return 0;
}

int kache_push_history_record(kache_history_record_t **history,
                              kache_history_record_t *record,
                              int *curr_size
                              int max_size)
{
    //max size of history reached, remove tail element
    if(*curr_size + 1 > max_size)
        dbg_err_if(kache_history_pop_last(history,max_size));
    else
        *curr_size = *curr_size + 1;
    int i;
    for(i = max_size; i!=0; i--)
        history[i] = history[i-1];
    kache_entry->history[0] = record;
    return 0;
err:
    return -1;

}
