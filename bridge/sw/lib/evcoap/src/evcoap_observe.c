#include "evcoap_base.h"
#include "evcoap_observe.h"

static ec_observer_t *ec_observer_new(const uint8_t *token, size_t token_sz, 
        const uint8_t *etag, size_t etag_sz, ec_mt_t media_type, 
        ec_msg_model_t msg_model, const ec_conn_t *conn);
static int ec_observer_add(ec_observation_t *obs, const uint8_t *token,
        size_t token_sz, const uint8_t *etag, size_t etag_sz, ec_mt_t mt, 
        ec_msg_model_t mm, const ec_conn_t *conn);
static ec_observer_t *ec_observer_search(ec_observation_t *obs, ec_conn_t *cn);
static void ec_observer_free(ec_observer_t *ovr);
static int ec_observer_push(ec_observation_t *obs, ec_observer_t *ovr);
static ec_observation_t *ec_observation_search(ec_t *coap, const char *uri);
static ec_observation_t *ec_observation_add(ec_t *coap, const char *uri, 
        ec_observe_cb_t cb, void *cb_args, uint32_t max_age);
ec_observation_t *ec_observation_new(const char *uri, ec_observe_cb_t cb, 
        void *cb_args, uint32_t max_age);
static bool ec_source_match(const ec_conn_t *req_src, const ec_conn_t *obs_src);
static int ec_source_copy(const ec_conn_t *src, ec_conn_t *dst);

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

    /* Copy-in the needed bits from the connection object. */
    dbg_err_if (ec_source_copy(conn, &ovr->conn));

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
    if (ovr)
        ec_observer_free(ovr);
    return -1;
}

static int ec_source_copy(const ec_conn_t *src, ec_conn_t *dst)
{
    dbg_return_if (src == NULL, -1);
    dbg_return_if (dst == NULL, -1);

    memcpy(&dst->peer, &src->peer, sizeof dst->peer);

    /* TODO copy in security context. */

    return 0;
}

static bool ec_source_match(const ec_conn_t *req_src, const ec_conn_t *obs_src)
{
    uint8_t peer_len;

    dbg_return_if (req_src == NULL, false);
    dbg_return_if (obs_src == NULL, false);

    dbg_err_if (ec_net_socklen(&req_src->peer, &peer_len));

    /* The source of a request is determined by the security mode used: with 
     * NoSec, it is determined by the source IP address and UDP port number. */
    if (!memcmp(&req_src->peer, &obs_src->peer, peer_len))
        return true;

    /* With other security modes, the source is also determined by the security
     * context. (TODO) */

    /* Fall through. */
err:
    return false;
}

static ec_observer_t *ec_observer_search(ec_observation_t *obs, ec_conn_t *conn)
{
    ec_observer_t *ovr;

    dbg_return_if (obs == NULL, NULL);
    dbg_return_if (conn == NULL, NULL);

    TAILQ_FOREACH(ovr, &obs->observers, next)
    {
        if (ec_source_match(conn, &ovr->conn))
            return ovr;
    }

    return NULL;
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
    ec_observation_t *obs, *new = NULL;

    dbg_return_if (srv == NULL, -1);
    dbg_return_if (cb == NULL, -1);

    /* Shortcuts (should they be assert'd?) */
    ec_t *coap = srv->base;
    ec_flow_t *flow = &srv->flow;

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
    ec_observer_t *ovr;
    ec_observation_t *obs;

    dbg_return_if (srv == NULL, -1);

    ec_flow_t *flow = &srv->flow;   /* shortcut */
    ec_t *coap = srv->base;         /* ditto */

    /* It's fine if the requested observation is not active, or there is no
     * such observer.  Just leave a trace in the (debug) log. */
    dbg_return_if (!(obs = ec_observation_search(coap, flow->urlstr)), 0);
    dbg_return_if (!(ovr = ec_observer_search(obs, &flow->conn)), 0);

    TAILQ_REMOVE(&obs->observers, ovr, next);
    ec_observer_free(ovr);

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



