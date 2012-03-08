#ifndef _EC_TIMER_H_
#define _EC_TIMER_H_

#include <u/libu.h>
#include <event2/event.h>

#include "evcoap_base.h"

struct ec_s;

struct ec_timer_s
{
    size_t retries_left;    /* >1 for counted timer (decremented when fires.) */
    struct event *evti;     /* timer event. */
    struct timeval tout;    /* timer interval. */
};
typedef struct ec_timer_s ec_timer_t;


int ec_timer_start(struct ec_s *coap, ec_timer_t *ti, size_t max_retry,
        void (*cb)(evutil_socket_t, short, void *), void *cb_args); 
int ec_timer_remove(ec_timer_t *ti); 
int ec_timer_restart(ec_timer_t *ti);

#endif  /* !_EC_TIMER_H_ */
