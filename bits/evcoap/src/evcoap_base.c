#include "evcoap_base.h"

static const char *ec_dup_key_new(ev_uint16_t mid, 
        struct sockaddr_storage *peer, char key[EC_DUP_KEY_MAX]);
static void ec_dup_zap(evutil_socket_t u0, short u1, void *c);

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

int ec_dups_init(ec_t *coap, ec_dups_t *dups)
{
    u_hmap_opts_t *opts = NULL;
    u_hmap_t *hmap = NULL;

    dbg_return_if (coap == NULL, -1);
    dbg_return_if (dups == NULL, -1);
    dbg_return_if (dups->map != NULL, 0);

    dbg_err_if (u_hmap_opts_new(&opts));

    /* Received PDUs are variable length, that calls for custom deallocation
     * function. */
    dbg_err_if (u_hmap_opts_set_val_type(opts, U_HMAP_OPTS_DATATYPE_POINTER));
    dbg_err_if (u_hmap_opts_set_val_freefunc(opts, ec_recvd_pdu_free));

    dbg_err_if (u_hmap_easy_new(opts, &hmap));
    u_hmap_opts_free(opts), opts = NULL;

    /* Attach the newly created hmap and supplied evcoap base. */
    dups->map = hmap;
    dups->base = coap;

    return 0;
err:
    if (opts)
        u_hmap_opts_free(opts);
    if (hmap)
        u_hmap_free(hmap);
    return -1;
}

ec_recvd_pdu_t *ec_dups_search(ec_dups_t *dups, ev_uint16_t mid, 
        struct sockaddr_storage *peer)
{
    ec_recvd_pdu_t *recvd;
    char key[EC_DUP_KEY_MAX];

    dbg_err_if (dups == NULL);
    dbg_err_if (peer == NULL);

    dbg_err_if (!ec_dup_key_new(mid, peer, key));

    if ((recvd = (ec_recvd_pdu_t *) u_hmap_easy_get(dups->map, key)))
        u_dbg("%s is a duplicate", key);

    return recvd;
err:
    return NULL;
}

int ec_dups_insert(ec_dups_t *dups, struct sockaddr_storage *ss,
        ev_uint16_t mid)
{
    char key[EC_DUP_KEY_MAX];
    ec_recvd_pdu_t *recvd = NULL;

    dbg_return_if (dups == NULL, -1);

    ec_t *coap = dups->base;

    /* Build its key. */
    dbg_err_if (!ec_dup_key_new(mid, ss, key));

    /* Create new received PDU record. */
    recvd = ec_recvd_pdu_new(key, coap, dups, ss, mid);
    dbg_err_if (recvd == NULL);

    /* Push it into the map. */
    dbg_err_if (u_hmap_easy_put(dups->map, key, (const void *) recvd));
    recvd = NULL;   /* Ownership is on libu. */

    return 0;
err:
    if (recvd) 
        ec_recvd_pdu_free(recvd);
    return -1;
}

int ec_dups_delete(ec_dups_t *dups, const char *key)
{
    dbg_return_if (dups == NULL, -1);
    dbg_return_if (key == NULL, -1);

    dbg_return_if (u_hmap_easy_del(dups->map, key), -1);

    return 0;
}

static void ec_dup_zap(evutil_socket_t u0, short u1, void *c)
{
    ec_recvd_pdu_t *recvd = (ec_recvd_pdu_t *) c; 

    u_dbg("Now removing stale received PDU with key '%s'", recvd->key);

    dbg_err_if (ec_dups_delete(recvd->dups, recvd->key));

    /* Fall through. */
err:
    return;
}

/* Key format is: "mid'+'IPaddr':'port" */
static const char *ec_dup_key_new(ev_uint16_t mid, 
        struct sockaddr_storage *peer, char key[EC_DUP_KEY_MAX])
{
    char ap[EC_DUP_KEY_MAX];
    const size_t ap_sz = sizeof ap;

    dbg_err_if (peer == NULL);
    dbg_err_if (key == NULL);

    (void) evutil_format_sockaddr_port((struct sockaddr *) peer, ap, ap_sz);

    dbg_err_if (u_snprintf(key, EC_DUP_KEY_MAX, "%u+%s", mid, ap));

    return key;
err:
    return NULL;
}

/* 
 * '0'  -> no dup
 * '1'  -> dup, (handled here ?)
 * '-1' -> internal error
 */
int ec_dups_handle_incoming_srvmsg(ec_dups_t *dups, ev_uint16_t mid, int sd,
        struct sockaddr_storage *ss)
{
    ec_recvd_pdu_t *recvd = NULL;

    dbg_return_if (dups == NULL, -1);
    dbg_return_if (ss == NULL, -1);

    u_unused_args(sd);  /* Unused for NON responses (may be needed for CON.) */

    /* See if this PDU was seen here already. */ 
    if ((recvd = ec_dups_search(dups, mid, ss)))
        return 1;

    /* New entry, push it into the cache. */
    dbg_err_if (ec_dups_insert(dups, ss, mid));

    return 0;
err:
    return -1;
}

int ec_dups_handle_incoming_climsg(ec_dups_t *dups, ev_uint16_t mid, int sd,
        struct sockaddr_storage *ss)
{
    ec_recvd_pdu_t *recvd = NULL;

    dbg_return_if (dups == NULL, -1);
    dbg_return_if (ss == NULL, -1);

    /* See if this PDU was seen here already. */ 
    if ((recvd = ec_dups_search(dups, mid, ss)))
    {
        ec_cached_pdu_t *pdu = &recvd->cached_pdu; 

        if (pdu->is_set)
        {
            dbg_err_if (ec_net_send(pdu->hdr, pdu->opts, pdu->opts_sz, 
                        pdu->payload, pdu->payload_sz, sd, ss));
        }

        return 1;
    }

    /* New entry, push it into the cache. */
    dbg_err_if (ec_dups_insert(dups, ss, mid));

    return 0;
err:
    return -1;
}

ec_recvd_pdu_t *ec_recvd_pdu_new(const char *key, ec_t *coap, ec_dups_t *dups,
        struct sockaddr_storage *ss, ev_uint16_t mid)
{
    struct event *t = NULL;
    struct timeval tout = { .tv_sec = EC_DUP_LIFETIME, .tv_usec = 0 };
    ec_recvd_pdu_t *recvd = NULL;

    dbg_return_if (key == NULL, NULL);
    dbg_return_if (coap == NULL, NULL);
    dbg_return_if (ss == NULL, NULL);

    /* Make room for the new received PDU trace. */
    dbg_err_sif ((recvd = u_zalloc(sizeof *recvd)) == NULL);

    /* Register creation time for this record. */
    dbg_err_if (evutil_gettimeofday(&recvd->when, NULL) == -1);

    /* Stick MID. */
    recvd->mid = mid;

    /* Embed the key and hmap reference so that the object can self-destroy in 
     * later ec_dup_zap() -- i.e. when the associated countdown has elapsed. */
    dbg_err_if (u_strlcpy(recvd->key, key, sizeof recvd->key));
    recvd->dups = dups;

    /* Stick peer address. */
    memcpy(&recvd->who, ss, sizeof recvd->who);

    /* Init self destruction timer. */
    t = event_new(coap->base, -1, EV_PERSIST, ec_dup_zap, recvd);
    dbg_err_if (t == NULL || evtimer_add(t, &tout));

    recvd->countdown = t, t = NULL;

    /* Newly created cached PDUs are unset. */
    recvd->cached_pdu.is_set = false;

    return recvd;
err:
    if (t)
        event_free(t);
    if (recvd)
        ec_recvd_pdu_free(recvd);

    return NULL;
}

void ec_recvd_pdu_free(void *arg)
{
    ec_recvd_pdu_t *recvd = (ec_recvd_pdu_t *) arg;

    if (recvd)
    {
        ec_cached_pdu_t *pdu = &recvd->cached_pdu;

        u_free(pdu->opts);
        u_free(pdu->payload);
        u_free(recvd);

        /* Remove timer. */
        if (recvd->countdown)
            event_free(recvd->countdown);
    }
}

int ec_recvd_pdu_update(ec_recvd_pdu_t *recvd, ev_uint8_t *hdr,
        ev_uint8_t *opts, size_t opts_sz, ev_uint8_t *payload, 
        size_t payload_sz)
{
    dbg_return_if (recvd == NULL, -1);

    ec_cached_pdu_t *pdu = &recvd->cached_pdu;

    /* Update all pieces. */
    memcpy(pdu->hdr, hdr, 4);
    pdu->opts = opts;
    pdu->opts_sz = opts_sz;
    pdu->payload = payload;
    pdu->payload_sz = payload_sz;

    pdu->is_set = true;

    return 0;
}
