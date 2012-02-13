#include "evcoap_observe.h"

int ec_observer_add(ec_server_t *srv, ec_observe_cb_t reps_cb, uint32_t max_age,
        ec_msg_model_t mm)
{
    dbg_return_if (srv == NULL, -1);
    dbg_return_if (reps_cb == NULL, -1);

    u_con("TODO add an observer for the given resource");

    return 0;
}

int ec_observer_del(ec_server_t *srv)
{
    dbg_return_if (srv == NULL, -1);
    u_con("TODO delete an observer for the given resource");
    return 0;
}

int ec_observe_flush(ec_server_t *srv)
{
    dbg_return_if (srv == NULL, -1);
    u_con("TODO force a notification for the given resource");
    return 0;
}

int ec_observe_chores(void)
{
    u_con("TODO I don't remember :-)");
    return 0;
}

int ec_observe_run(void)
{
    u_con("Execute a flush on the supplied observe queue");
    return 0;
}
