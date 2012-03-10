#include <u/libu.h>
#include "kache.h"

struct dummy {
    int dummy_val;
};

void f(kache_entry_t *kache_entry, void *arg)
{
    //dummy function, tests history and counter
    //char *out = (char*) arg;
    kache_entry_t *entry = (kache_entry_t*) kache_entry;
    //entry is fresh, access counter should be 0
    dbg_err_if(entry->access_counter!=0);
    kache_history_record_t *record;
    int in = 0;
    int i;
    //KACHE_HISTORY_FOREACH(record,entry)
    for(i = 0; i< kache_entry->history_size; i++)
    {
        //first history record should have its access counter
        //set to 2
        record = kache_entry->history[i];
        in=1;
        dbg_err_if(record->access_counter!=2);
        break;
    }
    dbg_err_if( in!= 1);
    strcpy((char *)arg,"OK");
    return;
err:
    strcpy((char *)arg,"KO");
    return;
}

static int init_push_get_del(u_test_case_t *tc)
{
    kache_t *kache;
    dbg_err_if((kache = kache_init()) == NULL);
    dbg_err_if( kache_init_data_structure(kache));
    struct dummy *du;
    dbg_err_if((du = malloc(sizeof(struct dummy))) == NULL);
    du->dummy_val = 222;
    dbg_err_if(kache_set(kache,"dummykey",(const void*) du));

    struct dummy *got;
    dbg_err_if( (got = kache_get(kache,"dummykey")) == NULL);
    dbg_err_if( got->dummy_val != 222);

    //test if overwrite behaves correctly
    struct dummy *overwrite;
    dbg_err_if((overwrite = malloc(sizeof(struct dummy))) == NULL);
    overwrite->dummy_val = 333; 
    dbg_err_if(kache_set(kache,"dummykey",(const void*) overwrite));
    dbg_err_if( (got = kache_get(kache,"dummykey")) == NULL);
    dbg_err_if( got->dummy_val != 333);

    //test set procedure
    char *buffer = malloc(3);
    dbg_err_if( kache_attach_set_procedure(kache,f,buffer));
    // testing counter 
    dbg_err_if( (got = kache_get(kache,"dummykey")) == NULL);

    // (now it should be 2)
    // test set procedure and stats:
    dbg_err_if(kache_set(kache,"dummykey",(const void*) overwrite));
    dbg_err_if(strcmp(buffer,"OK") !=  0);
    //test unset
    dbg_err_if( kache_unset(kache,"dummykey"));

    dbg_err_if( kache_get(kache,"dummykey") != NULL);
    kache_free(kache);
    free(buffer);
    return U_TEST_SUCCESS;
err:
    return U_TEST_FAILURE;
}
int compare_dummy(void *o1,void *o2)
{
    struct dummy *d1 = (struct dummy*)((kache_entry_t*) o1)->resource;
    struct dummy *d2 = (struct dummy*)((kache_entry_t*) o2)->resource;
    if(d1->dummy_val == d2->dummy_val )
        return 0;
    else if(d1->dummy_val > d2->dummy_val )
        return 1; // Structs with lower value should be discarded first
    else
        return -1;

}

static int custom_discard_policy(u_test_case_t *tc)
{
    kache_t *kache;
    u_test_err_if((kache = kache_init()) == NULL);
    dbg_err_if(kache_set_max_size(kache, 2));
    dbg_err_if(kache_set_custom_discard_policy(kache, compare_dummy));
    u_test_err_if(kache_init_data_structure(kache));
    struct dummy *du;
    int i = 0;
    char *key = malloc(2);
    for(i=0;i<3;i++)
    {
        u_test_err_if((du = malloc(sizeof(struct dummy))) == NULL);
        du->dummy_val = i;
        sprintf(key,"%d",i);
        u_test_err_if(kache_set(kache,key,(const void*) du));
    }
    u_test_err_if( (du = kache_get(kache,"0")) != NULL);
    u_test_err_if( (du = kache_get(kache,"2")) == NULL);
    u_test_err_if( (du = kache_get(kache,"1")) == NULL);
    u_test_err_if( du->dummy_val != 1 );
    kache_free(kache);
    free(key);
    return U_TEST_SUCCESS;
err:
    return U_TEST_FAILURE;
}
static int overwrite(u_test_case_t *tc)
{
    kache_t *kache;
    dbg_err_if((kache = kache_init()) == NULL);
    dbg_err_if(kache_init_data_structure(kache));
    struct dummy *du;
    dbg_err_if((du = malloc(sizeof(struct dummy))) == NULL);
    du->dummy_val = 222;
    char *key = "dummykey";
    dbg_err_if(kache_set(kache,key,(const void*) du));
    du = kache_get(kache,key);
    struct dummy *overwrite;
    dbg_err_if((overwrite = malloc(sizeof(struct dummy))) == NULL);
    overwrite->dummy_val = 333; 
    dbg_err_if(kache_set(kache,key,(const void*) overwrite));
    u_test_err_if((overwrite = kache_get(kache,key))==NULL);
    u_test_err_if(overwrite->dummy_val != 333);
    kache_free(kache);
    return U_TEST_SUCCESS;
err:
    return U_TEST_FAILURE;

}

int test_suite_common_tasks_register(u_test_t *t)
{
    u_test_suite_t *ts = NULL;

    dbg_err_if (u_test_suite_new("Kache common tasks and custom discard policy", &ts));
    dbg_err_if (u_test_case_register("init_push_get_del", init_push_get_del, ts));
    dbg_err_if (u_test_case_register("custom_discard_policy", custom_discard_policy, ts));
    dbg_err_if (u_test_case_register("overwrite", overwrite, ts));

    /* No dependencies. */

    return u_test_suite_add(ts, t);
err:
    u_test_suite_free(ts);
    return -1;
}
