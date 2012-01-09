#include <u/libu.h>
#include "evcoap_base.h"

static int test_0(u_test_case_t *tc)
{
    return U_TEST_SUCCESS;
}

int test_suite_dups_register(u_test_t *t)
{
    u_test_suite_t *ts = NULL;

    con_err_if (u_test_suite_new("CoAP duplicate handling", &ts));

    con_err_if (u_test_case_register("0", test_0, ts));

    /* No dependencies. */

    return u_test_suite_add(ts, t);
err:
    u_test_suite_free(ts);
    return -1;
}
