#ifndef _EC_OBSERVE_H_
#define _EC_OBSERVE_H_

#include <event2/event.h>

#include "evcoap_enums.h"
#include "evcoap_resource.h"
#include "evcoap_srv.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

/* Callback to be invoked to produce the resource representation(s) associated 
 * to the observed resource. */
typedef const uint8_t *(*ec_observe_cb_t)(const char *, ec_mt_t, size_t *, 
        void *);

struct ec_observer_s
{
    /* Token of the original request -- if any. */
    uint8_t token[8];
    size_t token_sz;

    /* Optional ETag in request (return Valid instead of Content.) */
    uint8_t etag[EC_ETAG_SZ];
    size_t etag_sz; /* MUST be <= 8; 0 means etag is not set. */

    /* Media type of the representation returned with the first GET. */
    ec_mt_t media_type;

    /* Messaging model in use for notifications. */
    ec_msg_model_t msg_model;

    /* Peer/end-point identification. */
    ec_conn_t conn;

    ec_observe_cb_t reps_cb;    /* Callback used for resource creation. */
    void *reps_cb_args;

    /* Next observer for this resource. */
    TAILQ_ENTRY(ec_observer_s) next;
};
typedef struct ec_observer_s ec_observer_t;

/* An observed resource -- with its observers attached. */
struct ec_observation_s
{
    char uri[EC_URI_MAX];       /* Observed resource identifier. */
    ec_res_t *cached_res;       /* Cached resource (with representations.) */
    uint32_t max_age;           /* Resource reload+notification timeout. */
    struct event *notify;       /* Notification timer. */

    TAILQ_HEAD(, ec_observer_s) observers;  /* Peers observing this resource. */
    TAILQ_ENTRY(ec_observation_s) next;         /* Next observed resource. */
};
typedef struct ec_observation_s ec_observation_t;

/* Add a new observer. */
int ec_add_observer(ec_server_t *srv, ec_observe_cb_t cb, void *cb_args,
        uint32_t max_age, ec_mt_t mt, ec_msg_model_t mm, const uint8_t *etag,
        size_t etag_sz); 

int ec_rem_observer(ec_server_t *srv);
int ec_trigger_notification(ec_server_t *srv);


int ec_observation_chores(void);
int ec_observation_run(void);


#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif  /* !_EC_ENUMS_H_ */
