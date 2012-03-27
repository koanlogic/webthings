#include <u/libu.h>

int facility = LOG_LOCAL0;

int test_suite_common_tasks_register(u_test_t *t);
int test_suite_kache_evcoap_register(u_test_t *t);

int main(int argc, char **argv)
{
    
    int rc;
    u_test_t *t = NULL;

    dbg_err_if (u_test_new("kache unit tests", &t));
    dbg_err_if (test_suite_common_tasks_register(t));
    dbg_err_if (test_suite_kache_evcoap_register(t));

    rc = u_test_run(argc, argv, t);
    u_test_free(t);

    return rc;
err:
    u_test_free(t);
    return EXIT_FAILURE;
}

