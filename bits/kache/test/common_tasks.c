#include <u/libu.h>
#include "kache.h"

struct dummy {
    int dummy_val;
};

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
    dbg_err_if( got->dummy_val != du->dummy_val);
    
    kache_request_t *req;
    int in = 0;
    KACHE_HISTORY_FOREACH(req,kache)
    {
        in=1;
        dbg_err_if( ((struct dummy*)req->resource)->dummy_val != du->dummy_val);
        dbg_err_if( strcmp(req->resource_key,"dummykey") != 0);
    } 
    con_err_if( in!= 1);
    con_err_if( kache_unset(kache,"dummykey"));

    con_err_if( kache_get(kache,"dummykey") != NULL);
    kache_free(kache);
    return U_TEST_SUCCESS;
err:
    return U_TEST_FAILURE;
}

int test_suite_common_tasks_register(u_test_t *t)
{
    u_test_suite_t *ts = NULL;

    con_err_if (u_test_suite_new("Kache commons tasks (init, set, get, unset, free", &ts));

    con_err_if (u_test_case_register("init_push_get_del", init_push_get_del, ts));

    /* No dependencies. */

    return u_test_suite_add(ts, t);
err:
    u_test_suite_free(ts);
    return -1;
}
