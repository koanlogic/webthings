#include "evcoap_base.h"
#include "evcoap_observe.h"

static ec_observer_t *ec_observer_new(const uint8_t *token, size_t token_sz, 
        const uint8_t *etag, size_t etag_sz, ec_mt_t media_type, 
        ec_msg_model_t msg_model, const ec_conn_t *conn);
static int ec_observer_add(ec_observation_t *obs, const uint8_t *token,
        size_t token_sz, const uint8_t *etag, size_t etag_sz, ec_mt_t mt, 
        ec_msg_model_t mm, const ec_conn_t *conn);
static void ec_observer_free(ec_observer_t *ovr);
static int ec_observer_push(ec_observation_t *obs, ec_observer_t *ovr);
static ec_observation_t *ec_observation_search(ec_t *coap, const char *uri);
static ec_observation_t *ec_observation_add(ec_t *coap, const char *uri, 
        ec_observe_cb_t cb, void *cb_args, uint32_t max_age);
ec_observation_t *ec_observation_new(const char *uri, ec_observe_cb_t cb, 
        void *cb_args, uint32_t max_age);

static ec_observer_t *ec_observer_new(const uint8_t *token, size_t token_sz, 
        const uint8_t *etag, size_t etag_sz, ec_mt_t media_type, 
        ec_msg_model_t msg_model, const ec_conn_t *conn)
{
    ec_observer_t *ovr = NULL;

    dbg_return_if (conn == NULL, NULL);
    dbg_return_if (token_sz > sizeof ovr->token, NULL);
    dbg_return_if (etag_sz > sizeof ovr->token, NULL);

    dbg_err_sif ((ovr = u_zalloc(sizeof *ovr)) == NULL);

    if (token && token_sz)
        memcpy(ovr->token, token, token_sz);

    if (etag && etag_sz)
        memcpy(ovr->etag, etag, etag_sz);

    ovr->media_type = media_type;
    ovr->msg_model = msg_model;

    /* TODO 
     * TODO copy-in the connection object (deep or shallow ?)
     * TODO */

    return ovr;
err:
    if (ovr)
        ec_observer_free(ovr);
    return NULL;
}

static int ec_observer_add(ec_observation_t *obs, const uint8_t *token,
        size_t token_sz, const uint8_t *etag, size_t etag_sz, ec_mt_t mt, 
        ec_msg_model_t mm, const ec_conn_t *conn)
{
    ec_observer_t *ovr = NULL;

    ovr = ec_observer_new(token, token_sz, etag, etag_sz, mt, mm, conn);
    dbg_err_ifm (ovr == NULL, "observer creation failed");

    dbg_err_if (ec_observer_push(obs, ovr));
    ovr = NULL;

    return 0;
err:
    return -1;
}

static void ec_observer_free(ec_observer_t *ovr)
{
    if (ovr)
        u_free(ovr);
    /* TODO conn object de-initialization ? */
    return;
}

static int ec_observer_push(ec_observation_t *obs, ec_observer_t *ovr)
{
    dbg_return_if (obs == NULL, -1);
    dbg_return_if (ovr == NULL, -1);

    TAILQ_INSERT_TAIL(&obs->observers, ovr, next);

    return 0;
}

static ec_observation_t *ec_observation_search(ec_t *coap, const char *uri)
{
    ec_observation_t *obs;

    TAILQ_FOREACH(obs, &coap->observing, next)
    {
        if (!evutil_ascii_strcasecmp(obs->uri, uri))
            return obs;
    }

    return NULL;
}

ec_observation_t *ec_observation_new(const char *uri, ec_observe_cb_t cb, 
        void *cb_args, uint32_t max_age)
{
    ec_observation_t *obs = NULL;

    dbg_return_if (cb == NULL, NULL);

    dbg_err_if ((obs = u_zalloc(sizeof *obs)) == NULL);
    dbg_err_if (u_strlcpy(obs->uri, uri, sizeof obs->uri));
    obs->reps_cb = cb;
    obs->reps_cb_args = cb_args;
    obs->max_age = max_age; /* TODO set a default max_age in case == 0 */

    TAILQ_INIT(&obs->observers);

    return obs;
err:
    return NULL;
}

static ec_observation_t *ec_observation_add(ec_t *coap, const char *uri, 
        ec_observe_cb_t cb, void *cb_args, uint32_t max_age)
{
    u_con("TODO");
    return 0;
}

static void ec_observation_free(ec_observation_t *obs)
{
    ec_observer_t *ovr;

    if (obs)
    {
        /* Delete observers. */
        while ((ovr = TAILQ_FIRST(&obs->observers)))
        {
            TAILQ_REMOVE(&obs->observers, ovr, next);
            ec_observer_free(ovr);
        }

        /* Drop resource representations. */
        if (obs->cached_res)
            ec_resource_free(obs->cached_res);

        u_free(obs); 
    }
    return;
}

/**
 *  \brief  user adds a new observer for the implicit resource using this I/F
 */ 
int ec_add_observer(ec_server_t *srv, ec_observe_cb_t cb, void *cb_args,
        uint32_t max_age, ec_mt_t mt, ec_msg_model_t mm, const uint8_t *etag, 
        size_t etag_sz)
{
    ec_t *coap;
    ec_flow_t *flow;
    ec_observation_t *obs = NULL, *new = NULL;

    dbg_return_if (srv == NULL, -1);
    dbg_return_if (cb == NULL, -1);

    /* Shortcuts (assert included.) */
    dbg_err_if ((coap = srv->base) == NULL);
    dbg_err_if ((flow = &srv->flow) == NULL);

    /* Check whether this resource is already observed. */
    if ((obs = ec_observation_search(coap, flow->urlstr)) == NULL)
    {
        /* Create a new observe record and stick it to the base. */
        new = ec_observation_add(coap, flow->urlstr, cb, cb_args, max_age);
        dbg_err_ifm (new == NULL, "could not observe %s", flow->urlstr);
    }

    /* Push the newly created observer to base. */
    dbg_err_if (ec_observer_add(obs ? obs : new, flow->token, flow->token_sz, 
                etag, etag_sz, mt, mm, &flow->conn));

    return 0;
err:
    if (new)
        ec_observation_free(new);
    return -1;
}

int ec_rem_observer(ec_server_t *srv)
{
    dbg_return_if (srv == NULL, -1);
    u_con("TODO delete an observer for the given resource");
    return 0;
}

int ec_trigger_notification(ec_server_t *srv)
{
    dbg_return_if (srv == NULL, -1);
    u_con("TODO force a notification for the given resource");
    return 0;
}

int ec_observation_chores(void)
{
    u_con("TODO I don't remember :-)");
    return 0;
}

int ec_observation_run(void)
{
    u_con("Execute a flush on the supplied observe queue");
    return 0;
}



