#ifndef _EC_OBSERVE_H_
#define _EC_OBSERVE_H_

#include <event2/event.h>

#include "evcoap_enums.h"
#include "evcoap_resource.h"
#include "evcoap_srv.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

typedef uint8_t *(*ec_observe_cb_t)(const char *, ec_mt_t, size_t *);

struct ec_observer_s
{
    /* Token of the original request -- if any. */
    uint8_t token[8];
    size_t token_sz;    

    /* Optional ETag in request (return Valid instead of Content.) */
    uint8_t etag[EC_ETAG_SZ];

    /* Media type of the representation returned with the first GET. */
    ec_mt_t media_type; 
};
typedef struct ec_observer_s ec_observer_t;

/* An observed resource -- with its observers attached. */
struct ec_observe_s
{
    char uri[EC_URI_MAX];       /* Observed resource identifier. */
    ec_msg_model_t msg_model;   /* Messaging model in use for notifications. */
    ec_observe_cb_t reps_cb;    /* Callback used for resource creation. */
    ec_res_t *cached_res;       /* Cached resource (with representations.) */

    TAILQ_HEAD(, ec_observer_s) observers;  /* Peers observing this resource. */
    TAILQ_ENTRY(ec_observe_s) next;         /* Next observed resource. */
};
typedef struct ec_observe_s ec_observe_t;

int ec_observer_add(ec_server_t *srv, ec_observe_cb_t reps_cb, uint32_t max_age,
        ec_msg_model_t mm);
int ec_observer_del(ec_server_t *srv);

int ec_observe_chores(void);
int ec_observe_run(void);

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif  /* !_EC_ENUMS_H_ */
