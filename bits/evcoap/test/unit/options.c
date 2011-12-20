#include <u/libu.h>
#include "evcoap_opt.h"

static int test_todo(u_test_case_t *tc)
{
    return U_TEST_SUCCESS;
}

int test_suite_options_register(u_test_t *t)
{
    u_test_suite_t *ts = NULL;

    con_err_if (u_test_suite_new("CoAP options", &ts));

    con_err_if (u_test_case_register("TODO", test_todo, ts));

    /* No dependencies. */

    return u_test_suite_add(ts, t);
err:
    u_test_suite_free(ts);
    return -1;
}
