#include <u/libu.h>
#include "kache.h"

struct dummy {
    int dummy_val;
};

int f(const void *kache_entry, const void *arg)
{
    //dummy function
    kache_entry_t *entry = (kache_entry_t*) kache_entry;
    dbg_err_if(entry->access_counter!=2);
    kache_history_record_t *record;
    int in = 0;
    KACHE_HISTORY_FOREACH(record,entry)
    {
        in=1;
        dbg_err_if(record->access_counter!=1);
    }
    dbg_err_if( in!= 1);
    return 0;
err:
    return -1;
}

static int init_push_get_del(u_test_case_t *tc)
{

    kache_t *kache;
    dbg_err_if((kache = kache_init()) == NULL);
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

    // testing counter 
    dbg_err_if( (got = kache_get(kache,"dummykey")) == NULL);
    // (now it should be 2)
    // test foreach and stats:
    dbg_err_if( kache_foreach_arg(kache,f, NULL));

    //test unset
    dbg_err_if( kache_unset(kache,"dummykey"));

    dbg_err_if( kache_get(kache,"dummykey") != NULL);
    kache_free(kache);
    return U_TEST_SUCCESS;
err:
    return U_TEST_FAILURE;
}

int test_suite_common_tasks_register(u_test_t *t)
{
    u_test_suite_t *ts = NULL;

    dbg_err_if (u_test_suite_new("Kache commons tasks (init, set, get, unset, free", &ts));

    dbg_err_if (u_test_case_register("init_push_get_del", init_push_get_del, ts));

    /* No dependencies. */

    return u_test_suite_add(ts, t);
err:
    u_test_suite_free(ts);
    return -1;
}
