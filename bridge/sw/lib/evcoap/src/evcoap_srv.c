#include <strings.h>
#include <err.h>
#include <u/libu.h>
#include "evcoap_srv.h"
#include "evcoap_base.h"
#include "evcoap_flow.h"
#include "evcoap_observe.h"
#include "evcoap_timer.h"

struct resched_userfn_args_s
{
    ec_server_t *srv;
    ec_server_cb_t f;
    void *f_args;
};

static struct resched_userfn_args_s *resched_userfn_args_new(ec_server_t *srv,
        ec_server_cb_t f, void *f_args);
static void resched_userfn_args_free(struct resched_userfn_args_s *a);

static ec_net_cbrc_t ec_server_handle_pdu(uint8_t *raw, size_t raw_sz, int sd,
        struct sockaddr_storage *peer, void *arg);
static int ec_server_userfn(ec_server_t *srv, ec_server_cb_t f, void *args, 
        struct timeval *tv, bool resched);
static int ec_server_reply(ec_server_t *srv, ec_rc_t rc, uint8_t *pl, 
        size_t pl_sz);
static int ec_server_check_transition(ec_srv_state_t cur, ec_srv_state_t next);
static int ec_trim_payload_sz(ec_cfg_t *cfg, size_t *pl_sz);
static int ec_server_new_response(ec_server_t *srv);
static int ec_server_add(ec_server_t *srv, ec_servers_t *srvs);
static int ec_server_del(ec_server_t *srv, ec_servers_t *srvs);
static ec_server_t *ec_servers_lookup(ec_servers_t *srvs, uint16_t mid, int sd, 
        struct sockaddr_storage *peer);
static bool ec_server_state_is_final(ec_srv_state_t state);
static int ec_server_reschedule_userfn(ec_server_cb_t f, ec_server_t *srv,
        void *args, const struct timeval *tv);
static void resched_userfn(evutil_socket_t u0, short u1, void *a);
static int ec_server_ready(ec_server_t *srv, bool is_con);

static int ec_srv_start_coap_timer(ec_server_t *srv);
static int ec_srv_restart_coap_timer(ec_server_t *srv);
static int ec_srv_stop_coap_timer(ec_server_t *srv);

int ec_servers_init(ec_servers_t *srvs)
{
    dbg_return_if (srvs == NULL, -1);

    TAILQ_INIT(&srvs->h);

    return 0;
}

void ec_servers_term(ec_servers_t *srvs)
{
    if (srvs != NULL)
    {
        ec_server_t *srv;

        while ((srv = TAILQ_FIRST(&srvs->h)))
        {
            (void) ec_server_del(srv, srvs);
            ec_server_free(srv);
        }
    }
    return;
}

static ec_server_t *ec_servers_lookup(ec_servers_t *srvs, uint16_t mid, int sd, 
        struct sockaddr_storage *peer)
{
    ec_server_t *srv;
    uint8_t peer_len;

    dbg_return_if (srvs == NULL, NULL);
    dbg_return_if (peer == NULL, NULL);

    dbg_err_if (ec_net_socklen(peer, &peer_len));

    /* XXX this would not work for multicast. */
    TAILQ_FOREACH(srv, &srvs->h, next)
    {
        size_t i;
        ec_conn_t *conn = &srv->flow.conn;

        if (conn->socket != sd || memcmp(&conn->peer, peer, peer_len))
            continue;

        /* May match any outbound PDU (i.e. a ->res or an ->octrl.) */
        ec_pdu_t *opdu[2] = { [0] = srv->octrl, [1] = srv->res };

        for (i = 0; i < 2; ++i)
        {
            if (opdu[i] && opdu[i]->hdr_bits.mid == mid)
                return srv;
        }
    }

err:
    return NULL;
}

static int ec_server_add(ec_server_t *srv, ec_servers_t *srvs)
{
    dbg_return_if (srv == NULL, -1);
    dbg_return_if (srvs == NULL, -1);

    TAILQ_INSERT_TAIL(&srvs->h, srv, next);
    srv->parent = srvs;

    return 0;
}

static int ec_server_del(ec_server_t *srv, ec_servers_t *srvs)
{
    dbg_return_if (srv == NULL, -1);
    dbg_return_if (srvs == NULL, -1);

    TAILQ_REMOVE(&srvs->h, srv, next);
    srv->parent = NULL;

    return 0;
}

ec_server_t *ec_server_new(struct ec_s *coap, evutil_socket_t sd)
{
    ec_server_t *srv = NULL;

    dbg_err_sif ((srv = u_zalloc(sizeof *srv)) == NULL);

    srv->base = coap;
    srv->parent = NULL;

    ec_flow_t *flow = &srv->flow;
    ec_conn_t *conn = &flow->conn;

    srv->res = srv->req = NULL;

    /* Clean output control message (hopefully they won't be needed.) */
    srv->octrl = NULL;

    return srv;
err:
    if (srv)
        ec_server_free(srv);
    return NULL;
}

int ec_server_wakeup(ec_server_t *srv)
{
    bool is_con = false;

    dbg_return_if (srv == NULL, -1);

    ec_t *coap = srv->base;
    ec_flow_t *flow = &srv->flow;
    ec_conn_t *conn = &flow->conn;

    dbg_return_if (ec_conn_get_confirmable(conn, &is_con), -1);

    return ec_server_ready(srv, is_con);
}

static int ec_server_new_response(ec_server_t *srv)
{
    ec_pdu_t *res = NULL;

    dbg_return_if (srv == NULL, -1);
    dbg_return_if (srv->res != NULL, -1);

    ec_flow_t *flow = &srv->flow;

    dbg_err_sif ((res = ec_pdu_new_empty()) == NULL);

    dbg_err_if (ec_pdu_set_flow(res, flow));

    /* Attach response PDU to the server context. */
    srv->res = res;

    return 0;
err:
    if (res)
        ec_pdu_free(res);
    return 0;
}

void ec_server_free(ec_server_t *srv)
{
    if (srv)
    {
        if (srv->res)
            ec_pdu_free(srv->res);

        if (srv->req)
            ec_pdu_free(srv->req);

        if (srv->octrl)
            ec_pdu_free(srv->octrl);

        ec_flow_term(&srv->flow);

        if (srv->parent)
            ec_server_del(srv, srv->parent);

        u_free(srv);
    }
}

ec_opts_t *ec_server_get_response_options(ec_server_t *srv)
{
    ec_pdu_t *res;
    ec_opts_t *opts;

    dbg_return_if (srv == NULL, NULL);

    dbg_err_if ((res = ec_server_get_response_pdu(srv)) == NULL);

    return &res->opts;
err:
    return NULL;

}

ec_opts_t *ec_server_get_request_options(ec_server_t *srv)
{
    ec_pdu_t *req;
    ec_opts_t *opts;

    dbg_return_if (srv == NULL, NULL);

    dbg_err_if ((req = ec_server_get_request_pdu(srv)) == NULL);

    return &req->opts;
err:
    return NULL;
}

void ec_server_input(evutil_socket_t sd, short u, void *arg)
{
    ec_t *coap = (ec_t *) arg;

    u_unused_args(u);

    ec_net_pullup_all(sd, ec_server_handle_pdu, coap);
}

static ec_net_cbrc_t ec_server_handle_pdu(uint8_t *raw, size_t raw_sz, int sd,
        struct sockaddr_storage *peer, void *arg)
{
    u_uri_t *u = NULL;
    ec_rescb_t *r;
    size_t olen = 0, plen;
    int flags = 0;
    ec_pdu_t *pdu = NULL;
    ec_server_t *srv = NULL;
    ec_t *coap;
    bool nosec = true, is_px;
    ec_rc_t rc = EC_RC_UNSET;

#define RC_ERR(resp_code, ...)  \
    do                          \
    {                           \
        u_dbg(__VA_ARGS__);     \
        rc = resp_code;         \
        goto err;               \
    } while (0)

    dbg_return_if ((coap = (ec_t *) arg) == NULL, EC_NET_CBRC_ERROR);
    dbg_return_if (raw == NULL, EC_NET_CBRC_ERROR);
    dbg_return_if (!raw_sz, EC_NET_CBRC_ERROR);
    dbg_return_if (sd == -1, EC_NET_CBRC_ERROR);
    dbg_return_if (peer == NULL, EC_NET_CBRC_ERROR);

    dbg_err_sif ((pdu = ec_pdu_new_empty()) == NULL);

    ec_hdr_t *h = &pdu->hdr_bits;    /* shortcut */

    /* Decode CoAP header. */
    dbg_err_if (ec_pdu_decode_header(pdu, raw, raw_sz));

    /* Pass MID and peer address to the dup handler machinery. */
    ec_dups_t *dups = &coap->dups;

    switch (ec_dups_handle_incoming_climsg(dups, h->mid, sd, peer))
    {
        case 0:
            /* Not a duplicate, proceed with normal processing. */
            break;
        case 1:
            /* Duplicate, possible resending of the paired message is handled 
             * by ec_dups_handle_incoming_climsg(). */
            goto cleanup;
        default:
            /* Internal error. */
            u_dbg("Duplicate handling machinery failed !");
            goto err;
    }

    /*
     * See what needs to be done based on the incoming PDU type (TODO factorize)
     */ 
    if (!h->code)
    {
        /* In case the incoming PDU is a control message (i.e. RST or ACK),
         * retrieve the active server context for this transaction.
         * An exception to this is a RST message from an observing client.
         * In this case there is no running server and the message must be
         * matched against the Observe machinery. */
        if (h->t == EC_COAP_RST)
        {
            /* Fake a flow object since we don't have one already (as
             * we don't have a srv context.) */
            ec_flow_t tflow;

            (void) ec_flow_init(&tflow);
            dbg_err_if (ec_conn_save_us(&tflow.conn, sd));
            dbg_err_if (ec_conn_save_peer(&tflow.conn, peer));
            (void) ec_pdu_set_flow(pdu, &tflow);

            /* Observations may be removed by RST'ing a notification message
             * so check whether this RST comes in response to an nfy PDU. */
            switch (ec_observe_canceled_by_rst(coap, pdu))
            {
                case 1:
                    /* Active observer removed. */
                    goto dump;
                default:
                    /* Proceed anyway. */
                    u_dbg("Observe handling machinery failed !");
                case 0:
                    /* Not an active observation: proceed as it should have
                     * an associated running server context. */
                    (void) ec_pdu_set_flow(pdu, NULL);
                    break;
            }
        }

        if ((srv = ec_servers_lookup(&coap->servers, h->mid, sd, peer)) == NULL)
        {
            RC_ERR(EC_BAD_REQUEST,
                    "no active server context on MID %u", h->mid);
        }
    }
    else if (EC_IS_METHOD(h->code))
    {
        /* On a brand new request, create a new server. */
        dbg_err_if ((srv = ec_server_new(coap, sd)) == NULL);
    }
    else
        RC_ERR(EC_BAD_REQUEST, "unexpected code %u", h->code);

    /* Make shortcuts to interesting sub-objects. */ 
    ec_pdu_t *res = srv->res;
    ec_pdu_t *req = srv->req;
    ec_pdu_t *octrl = srv->octrl;
    ec_flow_t *flow = &srv->flow;
    ec_conn_t *conn = &flow->conn;

    /* Save flow endpoints in the server context. */
    if (conn->socket != sd)
    {
        dbg_err_if (ec_conn_save_us(conn, sd));
        dbg_err_if (ec_conn_save_peer(conn, peer));
    }

    /* Attach the incoming PDU to the underlying flow. */
    dbg_err_if (ec_pdu_set_flow(pdu, flow));

    /* Again, check if its a "control" message. */
    if (!h->code)
    {
        /* Check if RST (we've already checked with the Observe machinery
         * that this PDU is not sent by a listening client.) */
        if (h->t == EC_COAP_RST)
        {
            /* Move server to final state and bail out. */
            ec_server_set_state(srv, EC_SRV_STATE_CLIENT_RST);
            goto dump;
        }
        else if (h->t == EC_COAP_ACK)
        {
            if (srv->state != EC_SRV_STATE_WAIT_ACK)
            {
                RC_ERR(EC_BAD_REQUEST, "unexpected ACK in %s",  
                        ec_srv_state_str(srv->state));
            }

            /* Move server context to a final state. */
            ec_server_set_state(srv, EC_SRV_STATE_RESP_DONE);
            goto dump;
        }
    }
    else
        (void) ec_server_set_msg_model(srv, h->t == EC_COAP_CON ? true : false);

    /* Decode options. */
    if (h->oc)
    {
        rc = ec_opts_decode(&pdu->opts, raw, raw_sz, h->oc, &olen);
        dbg_err_ifm (rc, "CoAP options could not be parsed correctly");
    }

    /* Attach payload, if any, to the server context. */
    if ((plen = raw_sz - (olen + EC_COAP_HDR_SIZE)))
        (void) ec_pdu_set_payload(pdu, raw + EC_COAP_HDR_SIZE + olen, plen);

    /* Save requested method. */
    dbg_err_if (ec_flow_set_method(flow, (ec_method_t) h->code));

    /* Save token into context. */
    ec_opt_t *t = ec_opts_get(&pdu->opts, EC_OPT_TOKEN);
    dbg_err_if (ec_flow_save_token(flow, t ? t->v : NULL, t ? t->l : 0));

    /* Recompose the requested URI and save it into the server context.
     * XXX Assume NoSec is the sole supported mode. */
    u = ec_opts_compose_url(&pdu->opts, &conn->us, nosec, &is_px);
    dbg_err_if (ec_flow_save_url(flow, u, is_px));
    u = NULL;   /* Ownership is given to flow_t */

    /* If enabled, dump the PDU (server=true).
       It cannot be done it any later because PDU is passed on. */
    if (getenv("EC_PLUG_DUMP"))
        (void) ec_pdu_dump(pdu, true);

    /* Everything has gone smoothly, so: attach the incoming PDU to the
     * request hook, create the and attach the response PDU, and set state 
     * accordingly. */
    (void) ec_server_set_req(srv, pdu), pdu = NULL;
    dbg_err_if (ec_server_new_response(srv));
    ec_server_set_state(srv, EC_SRV_STATE_REQ_OK);

    /* Observations may be removed by GET'ing the observed resource with
     * no Observe option.  On error just emit dbg message: we don't want 
     * to stop the processing flow only because the observe subsystem has
     * failed. */
    dbg_if (ec_observe_canceled_by_get(srv) == -1);

    /* Initialize the poll/wait timeout. */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 0 };

    /* Now it's time to invoke the callback registered for the requested URI,
     * or to fallback to generic URI handler if none matches. */
    TAILQ_FOREACH(r, &coap->resources, next)
    {
        if (!strcasecmp(r->path, flow->urlstr))
        {
            /* Invoke user callback. */
            dbg_err_if (ec_server_userfn(srv, r->cb, r->cb_args, &tv, false));
            return EC_NET_CBRC_SUCCESS;
        }
    }

    /* Fall back to catch-all function, if set, then fall through. */
    if (coap->fb)
    {
        dbg_err_if (ec_server_userfn(srv, coap->fb, coap->fb_args, &tv, false));
        return EC_NET_CBRC_SUCCESS;
    }

    /* Send 4.04 Not Found and fall through. */
    dbg_if (ec_server_reply(srv, EC_NOT_FOUND, NULL, 0));
    ec_server_set_state(srv, EC_SRV_STATE_RESP_DONE);

    return EC_NET_CBRC_SUCCESS;

dump:
    /* If enabled, dump the PDU (server=true). */
    if (getenv("EC_PLUG_DUMP"))
        (void) ec_pdu_dump(pdu, true);
cleanup:
    if (pdu)
        ec_pdu_free(pdu);
    if (u)
        u_uri_free(u);
    return EC_NET_CBRC_SUCCESS;
err:
    if (u) u_uri_free(u);
    if (srv)
    {
        /* Send the selected error (default to 5.00 Internal Server Error.) */
        dbg_if (ec_server_reply(srv, rc ? rc : EC_INTERNAL_SERVER_ERROR, 
                    NULL, 0));
        ec_server_set_state(srv, EC_SRV_STATE_INTERNAL_ERR);
    }
    if (pdu)
        ec_pdu_free(pdu);

    return EC_NET_CBRC_ERROR;
#undef RC_ERR
}

static int ec_trim_payload_sz(ec_cfg_t *cfg, size_t *pl_sz)
{
    size_t bsz;
    bool stateless_block;
    uint8_t szx;

    dbg_return_if (cfg == NULL, -1);
    dbg_return_if (pl_sz == NULL, -1);

    /* Retrieve block size information from configuration. */
    dbg_err_if (ec_cfg_get_block_info(cfg, &stateless_block, &szx));

    bsz = 1 << (szx + 4);

    /* See if this payload needs to be trimmed to the requested block 
     * boundary. */
    if (!stateless_block && *pl_sz > bsz)
        *pl_sz = bsz;

    return 0;
err:
    return -1;
}

static int ec_server_reply(ec_server_t *srv, ec_rc_t rc, uint8_t *pl, 
        size_t pl_sz)
{
    ec_flow_t *flow;
    ec_cfg_t *cfg;
        
    dbg_return_if (srv == NULL, -1);
    dbg_return_if (!EC_IS_RESP_CODE(rc), -1);

    flow = &srv->flow;
    cfg = &srv->base->cfg;

    /* Set response code. */
    dbg_err_if (ec_flow_set_resp_code(flow, rc));

    /* Stick payload to the response PDU, if supplied. */
    if (pl && pl_sz)
    {
        /* Do not handle Block here: just trunc payload to fit block size
         * if needed. */
        dbg_err_if (ec_trim_payload_sz(cfg, &pl_sz));
        dbg_err_if (ec_pdu_set_payload(srv->res, pl, pl_sz));
    }

    /* Send response PDU. */
    dbg_err_if (ec_server_send_resp(srv));

    return 0;
err:
    return -1;
}

static int ec_server_ready(ec_server_t *srv, bool is_con)
{
    dbg_return_if (srv == NULL, -1);

    if (srv->state == EC_SRV_STATE_ACK_SENT
            || srv->state == EC_SRV_STATE_REQ_OK)
    {
        /* Be it one-shot NON or CON w/piggyback ACK, or separate CON 
         * response or delayed NON, they are all handled the same way:
         * the ec_server_send_resp() function takes care of sending
         * what is needed depending on current FSM state. */
        dbg_err_if (ec_server_send_resp(srv));

        ec_server_set_state(srv, 
                is_con && srv->state == EC_SRV_STATE_ACK_SENT
                ? EC_SRV_STATE_WAIT_ACK
                : EC_SRV_STATE_RESP_DONE);
    }
    else
        dbg_err("unexpected state: %s", ec_srv_state_str(srv->state));

    return 0;
err:
    return -1;
}

static int ec_server_userfn(ec_server_t *srv, ec_server_cb_t f, void *args, 
        struct timeval *tv, bool resched)
{
    bool is_con = false, is_proxy = false;

    /* We do trust the caller here. */

    ec_t *coap = srv->base;
    ec_flow_t *flow = &srv->flow;
    ec_conn_t *conn = &flow->conn;

    dbg_err_if (ec_conn_get_confirmable(conn, &is_con));
    dbg_err_if (ec_flow_get_proxied(flow, &is_proxy));

    switch (f(srv, args, tv, resched))
    {
        case EC_CBRC_READY:
            dbg_err_if (ec_server_ready(srv, is_con));
            break;

        case EC_CBRC_WAIT:
            if (srv->state == EC_SRV_STATE_REQ_OK)
            {
                if (is_con)
                {
                    /* This will create the ->octrl PDU transparently. */
                    dbg_err_if (ec_server_send_separate_ack(srv));
                }
                dbg_err_if (ec_server_add(srv, &coap->servers));
                /* If this is a proxied flow, the user callback must not
                 * be rescheduled.  It is on the user to provide the return
                 * path callback programmatically. */
                if (!is_proxy)
                    dbg_err_if (ec_server_reschedule_userfn(f, srv, args, tv));
                /* Fake the ACK_SENT state for NON (this allows more uniform
                 * handling of actions.) */
                ec_server_set_state(srv, EC_SRV_STATE_ACK_SENT);
            }
            else if (srv->state == EC_SRV_STATE_ACK_SENT)
            {
                /* Bail out if user couldn't provide the requested resource
                 * in the advertised time. */
                dbg_err("user failed to timely provide separate response");
            }
            else
                dbg_err("unexpected state: %s", ec_srv_state_str(srv->state));

            break;

        case EC_CBRC_POLL:
            dbg_err("TODO handle client poll interface");

        case EC_CBRC_ERROR:
            /* This gets mapped to an internal error. */
            goto err;

        default:
            dbg_err("unknown return code from client callback !");
    }

    return 0;
err:
    return -1;
}

static struct resched_userfn_args_s *resched_userfn_args_new(ec_server_t *srv,
        ec_server_cb_t f, void *f_args)
{
    struct resched_userfn_args_s *a;
 
    dbg_err_sif ((a = u_zalloc(sizeof(struct resched_userfn_args_s))) == NULL);

    a->srv = srv;
    a->f = f;
    a->f_args = f_args;

    return a;
err:
    return NULL;
}

static void resched_userfn_args_free(struct resched_userfn_args_s *a)
{
    if (a)
        u_free(a);
    return;
}

static int ec_server_reschedule_userfn(ec_server_cb_t f, ec_server_t *srv,
        void *args, const struct timeval *tv)
{
    struct resched_userfn_args_s *a = NULL;

    dbg_return_if (f == NULL, -1);
    dbg_return_if (srv == NULL, -1);
    dbg_return_if (tv == NULL, -1);

    ec_t *coap = srv->base;
    ec_timer_t *ti = &srv->timers.resched;

    /* Pack arguments. */
    dbg_err_if ((a = resched_userfn_args_new(srv, f, args)) == NULL);

    /* Set reschedule timer and callback. */
    ti->tout = *tv;
    dbg_err_if (ec_timer_start(coap, ti, 1, resched_userfn, a));

    return 0;
err:
    if (a)
        resched_userfn_args_free(a);
    return -1;
}

static void resched_userfn(evutil_socket_t u0, short u1, void *a)
{
    struct timeval tv = { .tv_sec = 0, .tv_usec = 0 };
    struct resched_userfn_args_s *pack = (struct resched_userfn_args_s *) a;

    /* Unroll arguments. */
    ec_server_t *srv = pack->srv;
    ec_server_cb_t f = pack->f;
    void *f_args = pack->f_args;

    if (ec_server_userfn(srv, f, f_args, &tv, true))
        ec_server_set_state(srv, EC_SRV_STATE_INTERNAL_ERR);

    resched_userfn_args_free(a);
    return;
}

struct ec_s *ec_server_get_base(ec_server_t *srv)
{
    dbg_return_if (srv == NULL, NULL);

    return srv->base;
}

int ec_server_set_req(ec_server_t *srv, ec_pdu_t *req)
{
    dbg_return_if (srv == NULL, -1);
    dbg_return_if (req == NULL, -1);

    srv->req = req;

    return 0;
}

static bool ec_server_state_is_final(ec_srv_state_t state)
{
    switch (state)
    {
        case EC_SRV_STATE_INTERNAL_ERR:
        case EC_SRV_STATE_DUP_REQ:
        case EC_SRV_STATE_BAD_REQ:
        case EC_SRV_STATE_RESP_ACK_TIMEOUT:
        case EC_SRV_STATE_RESP_DONE:
        case EC_SRV_STATE_CLIENT_RST:
            return true;
        case EC_SRV_STATE_NONE:
        case EC_SRV_STATE_REQ_OK:
        case EC_SRV_STATE_ACK_SENT:
        case EC_SRV_STATE_WAIT_ACK:
        case EC_SRV_STATE_COAP_RETRY:
            return false;
        default:
            errx(EXIT_FAILURE, "%s: no such state %u", __func__, state);
    }
}

void ec_server_set_state(ec_server_t *srv, ec_srv_state_t state)
{
    ec_flow_t *flow = &srv->flow;
    ec_srv_state_t cur = srv->state;

    u_dbg("[server=%p] transition request from '%s' to '%s'",
            srv, ec_srv_state_str(cur), ec_srv_state_str(state));

    /* Check that the requested state transition is valid. */
    dbg_err_if (ec_server_check_transition(cur, state));

    /* Start retransmit timer after sending the separate CON response. */
    if (state == EC_SRV_STATE_WAIT_ACK)
    {
        if (cur == EC_SRV_STATE_ACK_SENT)
        {
            dbg_if (ec_flow_set_separate(flow, true));
            dbg_if (ec_srv_start_coap_timer(srv));
        }
        else if (cur == EC_SRV_STATE_COAP_RETRY)
            dbg_if (ec_srv_restart_coap_timer(srv));
    }

    if (ec_server_state_is_final((srv->state = state)))
    {
        dbg_if (ec_srv_stop_coap_timer(srv));
        ec_server_free(srv);
    }

    return;
err:
    errx(EXIT_FAILURE, "%s failed (see logs)", __func__);
}

static void ec_srv_coap_timeout(evutil_socket_t u0, short u1, void *s)
{
    ec_server_t *srv = (ec_server_t *) s;
    ec_dups_t *dups = &srv->base->dups;
    ec_timer_t *ti = &srv->timers.coap;

    if (ti->retries_left == 0)
        ec_server_set_state(srv, EC_SRV_STATE_RESP_ACK_TIMEOUT);
    else
    {
        /* Enter the RETRY state and re-send the separate response. */
        ec_server_set_state(srv, EC_SRV_STATE_COAP_RETRY);

        /* Send again and, if successful, re-enter the WAIT_ACK state. */
        dbg_err_if (ec_server_send_resp(srv));
        ec_server_set_state(srv, EC_SRV_STATE_WAIT_ACK);
    }

    return;
err:
    ec_server_set_state(srv, EC_SRV_STATE_INTERNAL_ERR);
    return;
}

static int ec_srv_start_coap_timer(ec_server_t *srv)
{
    dbg_return_if (srv == NULL, -1);

    ec_t *coap = srv->base;
    ec_timer_t *ti = &srv->timers.coap;

    /* Should be randomized. */
    ti->tout = (struct timeval){ .tv_sec = EC_COAP_RESP_TIMEOUT, .tv_usec = 0 };

    /* Create new CoAP (non persistent) timeout event for this client. */
    return ec_timer_start(coap, ti, EC_COAP_MAX_RETRANSMIT, 
            ec_srv_coap_timeout, srv);
}

static int ec_srv_restart_coap_timer(ec_server_t *srv)
{
    dbg_return_if (srv == NULL, -1);

    ec_t *coap = srv->base;
    ec_timer_t *ti = &srv->timers.coap;

    dbg_return_ifm (ti->retries_left == 0, -1, "CoAP timer exhausted");

    /* Double timeout value. */
    ti->tout.tv_sec *= 2;

    u_dbg("exp timeout = %ds", ti->tout.tv_sec);

    /* Decrement the retries left. */
    --ti->retries_left;

    /* Re-arm the CoAP timeout. */
    return ec_timer_restart(ti);
}

static int ec_srv_stop_coap_timer(ec_server_t *srv)
{
    dbg_return_if (srv == NULL, -1);

    ec_srv_timers_t *ti = &srv->timers;

    return ec_timer_remove(&ti->coap);
}

static int ec_server_check_transition(ec_srv_state_t cur, ec_srv_state_t next)
{
    switch (next)
    {
        /* Any state can switch to internal error. */
        case EC_CLI_STATE_INTERNAL_ERR:
            break;

        case EC_SRV_STATE_DUP_REQ:
        case EC_SRV_STATE_BAD_REQ:
        case EC_SRV_STATE_REQ_OK:
            dbg_err_if (cur != EC_SRV_STATE_NONE);
            break;

        case EC_SRV_STATE_ACK_SENT:
            dbg_err_if (cur != EC_SRV_STATE_REQ_OK
                    && cur != EC_SRV_STATE_WAIT_ACK);
            break;

        case EC_SRV_STATE_WAIT_ACK:
            dbg_err_if (cur != EC_SRV_STATE_ACK_SENT
                    && cur != EC_SRV_STATE_COAP_RETRY);
            break;

        case EC_SRV_STATE_RESP_ACK_TIMEOUT:
            dbg_err_if (cur != EC_SRV_STATE_WAIT_ACK);
            break;

        case EC_SRV_STATE_RESP_DONE:
            dbg_err_if (cur != EC_SRV_STATE_REQ_OK
                    && cur != EC_SRV_STATE_WAIT_ACK
                    && cur != EC_SRV_STATE_ACK_SENT);   /* XXX only for NON ! */
            break;

        case EC_SRV_STATE_COAP_RETRY:
            dbg_err_if (cur != EC_SRV_STATE_WAIT_ACK);
            break;

        case EC_SRV_STATE_CLIENT_RST:
            /* Any non-final ?  Check this out. */
            break;

        case EC_SRV_STATE_NONE:
        default:
            goto err;
    }

    return 0;
err:
    return -1;
}

int ec_server_send_resp(ec_server_t *srv)
{
    bool is_con, is_sep;

    dbg_return_if (srv == NULL, -1);
    dbg_return_if (srv->res == NULL, -1);

    /* The sibling need to be set before actual send is performed on the PDU 
     * (MID mirroring.) */
    if (srv->state != EC_SRV_STATE_ACK_SENT)
        dbg_err_if (ec_pdu_set_sibling(srv->res, srv->req));

    /* Consistency check:
     * - response code
     * - payload in case response code is Content
     * - other ?  */
    ec_flow_t *flow = &srv->flow;   /* shortcut */
    dbg_err_if (!EC_IS_RESP_CODE(flow->resp_code));

    /* Check if separate. */
    dbg_if (ec_flow_get_separate(flow, &is_sep));

    /* Need a payload in case response code is 2.05 Content ? */
    ec_pdu_t *res = srv->res;       /* shortcut */
/*  dbg_err_if (flow->resp_code == EC_CONTENT && res->payload == NULL); */

    ec_conn_t *conn = &flow->conn;  /* shortcut */
    dbg_err_if (ec_conn_get_confirmable(conn, &is_con));

    /* Encode, in case it was not already ACK'd, use piggyback. */
    if (is_con && !is_sep && srv->state != EC_SRV_STATE_ACK_SENT)
        dbg_err_if (ec_pdu_encode_response_piggyback(res));
    else
        dbg_err_if (ec_pdu_encode_response_separate(res));

    /* Send response PDU. */
    ec_dups_t *dups = &srv->base->dups;
    dbg_err_if (ec_pdu_send(res, dups));

    return 0;
err:
    return -1;
}

int ec_server_send_separate_ack(ec_server_t *srv)
{
    ec_pdu_t *sep_ack = NULL;

    dbg_return_if (srv == NULL, -1);
    dbg_return_if (srv->state != EC_SRV_STATE_REQ_OK, -1);
    dbg_return_if (srv->octrl != NULL, -1);

    /* Use output ctrl PDU to encode the separate ACK. */

    ec_dups_t *dups = &srv->base->dups;

    dbg_err_if ((sep_ack = ec_pdu_new_empty()) == NULL);

    dbg_err_if (ec_pdu_set_sibling(sep_ack, srv->req));
    dbg_err_if (ec_pdu_set_flow(sep_ack, &srv->flow));

    dbg_err_if (ec_pdu_encode_response_ack(sep_ack));
    dbg_err_if (ec_pdu_send(sep_ack, dups));

    srv->octrl = sep_ack;

    return 0;
err:
    if (sep_ack)
        ec_pdu_free(sep_ack);
    return -1;
}

const char *ec_server_get_url(ec_server_t *srv)
{
    dbg_return_if (srv == NULL, NULL);

    return ec_flow_get_urlstr(&srv->flow);
}

ec_method_t ec_server_get_method(ec_server_t *srv)
{
    dbg_return_if (srv == NULL, EC_METHOD_UNSET);

    return ec_flow_get_method(&srv->flow);
}

int ec_server_set_msg_model(ec_server_t *srv, bool is_con)
{
    dbg_return_if (srv == NULL, -1);

    return ec_conn_set_confirmable(&srv->flow.conn, is_con);
}

ec_pdu_t *ec_server_get_request_pdu(ec_server_t *srv)
{
    dbg_return_if (srv == NULL, NULL);

    return srv->req;
}

ec_pdu_t *ec_server_get_response_pdu(ec_server_t *srv)
{
    dbg_return_if (srv == NULL, NULL);

    return srv->res;
}
