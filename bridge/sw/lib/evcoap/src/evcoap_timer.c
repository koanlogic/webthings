#include <u/libu.h>

#include "evcoap_base.h"
#include "evcoap_timer.h"

/* The 'ti' object shall enter here with the .tout field already set by the
 * caller. */
int ec_timer_start(ec_t *coap, ec_timer_t *ti, size_t max_retry,
        void (*cb)(evutil_socket_t, short, void *), void *cb_args)
{
    dbg_return_if (coap == NULL, -1);
    dbg_return_if (ti == NULL, -1);
    dbg_return_if (cb == NULL, -1);
    dbg_return_if (!max_retry, -1);

    dbg_return_ifm (ti->evti != NULL, -1,
            "timer %p already initialized !", ti->evti);

    ti->retries_left = max_retry;

    /* Create and start timer. */
    dbg_err_if ((ti->evti = evtimer_new(coap->base, cb, cb_args)) == NULL);
    dbg_err_if (evtimer_add(ti->evti, &ti->tout));

    return 0;
err:
    ec_timer_remove(ti);
    return -1;
}

int ec_timer_remove(ec_timer_t *ti)
{
    dbg_return_if (ti == NULL, -1);

    if (ti->evti)
    {
        event_free(ti->evti);
        ti->evti = NULL;
        ti->retries_left = 0;
        /* Don't cleanup .tout which may be reused. */
    }

    return 0;
}

int ec_timer_restart(ec_timer_t *ti)
{
    dbg_return_if (ti == NULL, -1);

    /* Drop it in case the old instance is pending in the base, and
     * make it newly active with the configured timeout. */
    dbg_return_if (evtimer_del(ti->evti), -1);
    dbg_return_if (evtimer_add(ti->evti, &ti->tout), -1);

    return 0;
}


