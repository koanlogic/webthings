#include "evcoap_base.h"

int ec_listeners_add(ec_t *coap, evutil_socket_t sd)
{
    ec_listener_t *l = NULL;

    dbg_return_if (coap == NULL, -1);
    dbg_return_if (sd == -1, -1);

    dbg_err_if ((l = ec_listener_new(coap, sd)) == NULL);

    /* Register this listener. */
    TAILQ_INSERT_TAIL(&coap->listeners, l, next);

    return 0;
err:
    return -1;
}

ec_listener_t *ec_listener_new(ec_t *coap, evutil_socket_t sd)
{
    ec_listener_t *l = NULL;
    struct event *ev = NULL;

    dbg_return_if (coap == NULL, NULL);
    dbg_return_if (sd == -1, NULL);

    dbg_err_if ((l = u_zalloc(sizeof *l)) == NULL);

    dbg_err_if ((ev = event_new(coap->base, sd, EV_READ | EV_PERSIST,
                    ec_server_input, coap)) == NULL);

    dbg_err_if (event_add(ev, NULL) == -1);

    l->ev_input = ev, ev = NULL;
    l->sd = sd;

    return l;
err:
    ec_listener_free(l);
    return NULL;
}

void ec_listener_free(ec_listener_t *l)
{
    if (l)
    {
        if (l->ev_input)
            event_free(l->ev_input);
        u_free(l);
    }

    return;
}

