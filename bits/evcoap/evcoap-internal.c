#include <stdarg.h>
#include <u/libu.h>
#include <event2/event.h>
#include <event2/listener.h>

#include "evcoap.h"
#include "evcoap-internal.h"

/* From evutil-internal.h */
const char *evutil_format_sockaddr_port(const struct sockaddr *sa, char *out,
        size_t outlen);

/* Hook to libu debug. */
extern int facility;

/* CoAP message types. */
/* Map hdr.T to human readable strings. */
const char *evcoap_pdu_types[] =
{
    [EVCOAP_PDU_TYPE_CON] = "CON",
    [EVCOAP_PDU_TYPE_NON] = "NON",
    [EVCOAP_PDU_TYPE_ACK] = "ACK",
    [EVCOAP_PDU_TYPE_RST] = "RST"
};

const char *evcoap_msg_types[] =
{
    [EVCOAP_MSG_TYPE_EMPTY]    = "Empty",
    [EVCOAP_MSG_TYPE_REQ]      = "Request",
    [EVCOAP_MSG_TYPE_RESP]     = "Response",
    [EVCOAP_MSG_TYPE_RESERVED] = "Reserved",
    [EVCOAP_MSG_TYPE_UNSET]    = "##Unset##"
};

const char *evcoap_methods[] =
{
    [EVCOAP_METHOD_UNSET]  = "-",
    [EVCOAP_METHOD_GET]    = "GET",
    [EVCOAP_METHOD_POST]   = "POST",
    [EVCOAP_METHOD_PUT]    = "PUT",
    [EVCOAP_METHOD_DELETE] = "DELETE"
};

struct evcoap_opt_rec {
    size_t n;               /* Option number. */
    const char *s;          /* Option human readable name. */
    evcoap_opt_type_t t;
} g_opts[] = {
    { 0, "Invalid", EVCOAP_OPT_TYPE_INVALID },
    { 1, "Content-Type", EVCOAP_OPT_TYPE_UINT },
    { 2, "Max-Age", EVCOAP_OPT_TYPE_UINT },
    { 3, "Proxy-URI", EVCOAP_OPT_TYPE_STRING },
    { 4, "ETag", EVCOAP_OPT_TYPE_OPAQUE },
    { 5, "URI-Host", EVCOAP_OPT_TYPE_STRING },
    { 6, "Location-Path", EVCOAP_OPT_TYPE_STRING },
    { 7, "URI-Port", EVCOAP_OPT_TYPE_UINT },
    { 8, "Location-Query", EVCOAP_OPT_TYPE_STRING },
    { 9, "URI-Path", EVCOAP_OPT_TYPE_STRING },
    { 10, "Observe", EVCOAP_OPT_TYPE_UINT },
    { 11, "Token", EVCOAP_OPT_TYPE_OPAQUE },
    { 12, "Accept", EVCOAP_OPT_TYPE_UINT },
    { 13, "If-Match", EVCOAP_OPT_TYPE_OPAQUE },
    { 14, "Max-OFE", EVCOAP_OPT_TYPE_UINT },
    { 15, "URI-Query", EVCOAP_OPT_TYPE_STRING },
    { 21, "If-None-Match", EVCOAP_OPT_TYPE_EMPTY }
};

#define EVCOAP_OPTS_MAX (sizeof g_opts / sizeof(struct evcoap_opt_rec))

evutil_socket_t evcoap_do_bind_socket(struct sockaddr_storage *ss,
        ev_socklen_t ss_len)
{
    int sd = -1;
    const struct sockaddr *sa = (const struct sockaddr *) ss;
    
    dbg_err_sif ((sd = socket(sa->sa_family, SOCK_DGRAM, 0)) == -1);
    dbg_err_sif (bind(sd, sa, ss_len) == -1);

    return sd;
err:
    return -1;
}

/* Return NULL if there is no payload, or a pointer to constant data referencing
 * the beginning of the payload in the PDU. */
const ev_uint8_t *evcoap_pdu_get_payload(struct evcoap_pdu *pdu, size_t *plen)
{
    dbg_return_if (pdu == NULL, NULL);

    if (EVCOAP_PDU_EMPTY(pdu))
    {
        *plen = 0;
        return NULL;
    }

    *plen = (pdu->data + pdu->datalen) - pdu->payload;

    return pdu->payload;
}

void evcoap_cb_free(struct evcoap_cb *cb)
{
    if (cb)
    {
        u_free(cb->path);
        u_free(cb->ack_timeout);
        u_free(cb);
    }
}

void evcoap_pending_ack_free(struct evcoap_pending_ack *pack)
{
    u_free(pack);
    return;
}

void evcoap_pending_acks_chores (evutil_socket_t u0, short u1, void *c)
{
    struct timeval now, elapsed;
    struct evcoap_pending_ack *pack;
    struct evcoap *coap = (struct evcoap *) c;

    u_unused_args(u0, u1);

    dbg_err_sif (event_base_gettimeofday_cached(coap->base, &now));

    TAILQ_FOREACH (pack, &coap->pending_acks, next)
    {
        evutil_timersub(&now, &pack->when, &elapsed);

        if (evutil_timercmp(&elapsed, &pack->timeout, >=))
        {
            ev_uint8_t hdr[4];

            /* Build ACK for the given MID. */
            evcoap_build_header(COAP_PROTO_VER_1, EVCOAP_PDU_TYPE_ACK, 0, 
                    EVCOAP_MSG_TYPE_EMPTY, pack->mid, hdr);

            /* Send an header only PDU. */
            dbg_if (evcoap_send(coap, pack->sd, &pack->ss, pack->ss_len, 
                        hdr, NULL, 0, NULL, 0));

            /* Remove sent ACK from queue. */
            TAILQ_REMOVE(&coap->pending_acks, pack, next);
            evcoap_pending_ack_free(pack);
        }
    }
err:
    return;
}

void evcoap_build_header(ev_uint8_t ver, ev_uint8_t t, ev_uint8_t oc, 
        ev_uint8_t code, ev_uint16_t mid, ev_uint8_t hdr[4])
{
    hdr[0] = ((ver & 0x03) << 6) | ((t & 0x03) << 4) | (oc & 0x0f);
    hdr[1] = code;
    hdr[2] = (htons(mid) & 0xff00) >> 8;
    hdr[3] = htons(mid) & 0x00ff;
}

int evcoap_send(struct evcoap *coap, int sd, 
        const struct sockaddr_storage *ss, ev_socklen_t ss_len,
        const ev_uint8_t *hdr, const ev_uint8_t *opts, size_t opts_len,
        const ev_uint8_t *payload, size_t payload_len)
{
    struct msghdr msg;
    struct iovec iov[3];
    size_t iov_idx = 0;
   
    /* Header is non optional. */
    iov[iov_idx].iov_base = (void *) hdr;
    iov[iov_idx].iov_len = 4;
    ++iov_idx;

    /* Add options, if any. */
    if (opts && opts_len)
    {
        iov[iov_idx].iov_base = (void *) opts;
        iov[iov_idx].iov_len = opts_len;
        ++iov_idx;
    }
    
    /* Add payload, if any. */
    if (payload && payload_len)
    {
        iov[iov_idx].iov_base = (void *) payload;
        iov[iov_idx].iov_len = payload_len;
        ++iov_idx;
    }

    msg.msg_name = (void *) ss;
    msg.msg_namelen = ss_len;
    msg.msg_iov = iov;
    msg.msg_iovlen = iov_idx;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    dbg_err_sif (sendmsg(sd, &msg, 0) == -1);

    /* TODO Try to attach this message to the duplicate queue
     * (perhaps we need a req|resp flag indication from the caller) */

    return 0;
err:
    return -1;
}

void evcoap_rcvd_queue_chores (evutil_socket_t u0, short u1, void *arg)
{
    time_t now;
    struct evcoap_rcvd_pdu *rcvd;
    struct evcoap *coap = (struct evcoap *) arg;

    u_unused_args(u0, u1);

    /* Use coarse grained clock here. */
    now = time(NULL);

    TAILQ_FOREACH (rcvd, &coap->rcvd_queue, next)
    {
        if (((now - rcvd->when.tv_sec)) > EVCOAP_RCVD_TTL_MAX)
        {
            EVCOAP_TRACE("Delete entry for MID %u", rcvd->mid);

            TAILQ_REMOVE(&coap->rcvd_queue, rcvd, next);
            evcoap_rcvd_pdu_free(rcvd);
        }
    }

    return;
}

void evcoap_input (int sd, short what, void *coap)
{
    int e; 
    ev_ssize_t n;
    struct sockaddr_storage peer;
    ev_socklen_t peer_len = sizeof(peer);
    ev_uint8_t d[COAP_REQUEST_SIZE_MAX];

    u_unused_args(what);

    /* 
     * Process all buffered messages.
     */
    for (;;)
    {
        /* Pull up next UDP packet from the socket input buffer. */
        n = recvfrom(sd, (void *) d, sizeof d, 0, 
                (struct sockaddr *) &peer, &peer_len);

        /* XXX What happens if the received CoAP packet is greater than
         * XXX COAP_REQUEST_SIZE_MAX (silent truncation, error, read split
         * XXX through multiple recvfrom(), etc.) ?  See Stevens' TCP/IP 
         * XXX Illustrated vol.1, pg 160. Rather discouraging. */ 

        /* Skip empty UDP datagrams. */
        if (n == 0)
            continue;

        /* Check for errors. */
        if (n < 0)
        {
            e = evutil_socket_geterror(sd);
            if (e == EINTR || e == EAGAIN)
                return;

            u_warn("%s", evutil_socket_error_to_string(e));
            return;
        }

        /* Go and parse the CoAP message. */
        evcoap_pdu_parse(coap, d, (size_t) n, sd, &peer, peer_len);
    }

    return;
}

int evcoap_bound_socket_get_secure(struct evcoap *coap, int sd, 
        ev_uint8_t *psecure)
{
    struct evcoap_bound_socket *bs;

    /* Trust the caller. */

    TAILQ_FOREACH(bs, &coap->sockets, next)
    {
        if (bs->sd == sd)
        {
            *psecure = bs->secure;
            return 0;
        }
    }

    return -1;
}

int evcoap_pending_ack_sched(struct evcoap *coap, ev_uint16_t mid,
        const struct timeval *tout, evutil_socket_t sd, 
        const struct sockaddr_storage *ss, ev_socklen_t ss_len)
{
    struct timeval now;
    struct evcoap_pending_ack *pack = NULL;

    dbg_err_if (event_base_gettimeofday_cached(coap->base, &now));
    dbg_err_sif ((pack = u_malloc(sizeof *pack)) == NULL);
    pack->mid = mid;
    pack->timeout = *tout;
    pack->when = now;
    pack->sd = sd;
    pack->ss = *ss;
    pack->ss_len = ss_len;

    TAILQ_INSERT_TAIL(&coap->pending_acks, pack, next);
    pack = NULL;

    return 0;
err:
    return -1;
}

void evcoap_pdu_parse(struct evcoap *coap, const ev_uint8_t *d,
        size_t dlen, int sd, const struct sockaddr_storage *peer,
        const ev_socklen_t peer_len)
{
    ev_uint8_t hdr[4];
    struct evcoap_cb *cb = NULL;
    struct evcoap_pdu *pdu = NULL;
    ev_uint8_t secure = 0;
    const char *mp = NULL; 
    int flags = FNM_PATHNAME | FNM_PERIOD | FNM_CASEFOLD | FNM_LEADING_DIR;
    
    /* Trust the caller. */

    /* Lookup the secure attribute. */
    dbg_err_ifm (evcoap_bound_socket_get_secure(coap, sd, &secure),
            "%d not registered", sd);

    /* Internalize the PDU. */
    dbg_err_ifm (!(pdu = evcoap_pdu_new_received(coap, sd, d, dlen, secure,
                    peer, peer_len)),
            "request message creation failed");

    /* Retrieve the URI, if available. */
    mp = u_uri_get_path(pdu->uri);

    /* Dispatch parsed message to the user supplied callback. */
    TAILQ_FOREACH(cb, &coap->callbacks, next)
    {
        evcoap_cb_status_t rc;

        /* See 'flags' for details on matching. */
        if (fnmatch(cb->path, mp, flags) == FNM_NOMATCH)
            continue;

        /* BEWARE: ownership of the PDU is transferred to the callback. */
        rc = cb->fn(pdu, mp, cb->fn_args);

        /* Ok, we got a callback for the requested URL.  First off, check 
         * whether the user set an auto ACK timeout, in which case the action
         * is scheduled to happen automatically when timeout elapses (unless
         * it is voided by the related user response being sent in the 
         * meanwhile.) */
        if (pdu->t == EVCOAP_PDU_TYPE_CON
                && rc == EVCOAP_CB_STATUS_ACK_AUTO)
        {
            dbg_err_if (evcoap_pending_ack_sched(coap, pdu->mid, 
                        cb->ack_timeout, sd, peer, peer_len));
        }

        return;
    }

    /* Fall back to catch-all function, if set. */
    if (coap->fb)
        coap->fb(pdu, mp, coap->fb_args);

    /* User did not provide a callback for this URL: send back a 4.04. */
    evcoap_build_header(COAP_PROTO_VER_1, pdu->t, 0, EVCOAP_RESP_CODE_NOT_FOUND,
            pdu->mid, hdr);
    dbg_if (evcoap_send(coap, sd, peer, peer_len, hdr, NULL, 0, NULL, 0));

    /* TODO */

    return;
err:
    /* TODO decide what to do in case an internal error occurs here,
     * TODO i.e. silently discard or return an error indication 
     * TODO (EVCOAP_RESP_CODE_INTERNAL_SERVER_ERROR) to our peer. */
    if (pdu)
        evcoap_pdu_free(pdu);
    return;
}

int evcoap_pdu_uri_compose_proxy(struct evcoap_pdu *pdu)
{
    char pxu[U_URI_STRMAX] = { '\0' };
    struct evcoap_opt *opt;

    /* Trust the caller. */

    /* "Proxy-URI MAY occur one or more times and MUST take precedence over
     * any of the Uri-Host, Uri-Port, Uri-Path or Uri-Query options." */
    TAILQ_FOREACH(opt, &pdu->options, next) 
    {
        /* Reassemble all Proxy-URI fragments. */
        if (opt->sym == EVCOAP_OPT_PROXY_URI)
        {
            dbg_return_if (u_strlcat(pxu, evcoap_opt_get_string_pretty(opt),
                        sizeof pxu), -1);
            return 0;
        }
    }

    /* Decompose into pieces. */
    return (pxu[0] != '\0') ? u_uri_crumble(pxu, 0, &pdu->uri) : -1;
}

/* TODO May host and port be absent ?  If yes, what do we use ? */
int evcoap_pdu_uri_compose_tokens(struct evcoap_pdu *pdu)
{
    u_uri_t *u = NULL;
    struct evcoap_opt *opt;
    char host[EVCOAP_OPT_LEN_MAX + 1], port[EVCOAP_OPT_LEN_MAX + 1],
         path[U_URI_STRMAX], query[U_URI_STRMAX], authority[U_URI_STRMAX];

    /* Initialize tokens to empty. */
    host[0] = port[0] = path[0] = query[0] = authority[0] = '\0';

    TAILQ_FOREACH(opt, &pdu->options, next)
    {
        /* 
         * Spec says: "Uri-Host and Uri-Port MUST NOT occur more than once",
         * instead we relax this and just ignore possible duplicates.
         */

        if (opt->sym >= EVCOAP_OPT_URI_HOST
                && host[0] == '\0'
                && authority[0] == '\0')
        {
            if (opt->sym > EVCOAP_OPT_URI_HOST)
            {
                char a[sizeof host]; 
                const char *ap;

                /* "The default value of the Uri-Host Option is the IP literal
                 *  representing the destination IP address of the request 
                 *  message" */
                ap = evutil_format_sockaddr_port((struct sockaddr *)&pdu->me,
                        a, sizeof a);

                /* Cook the whole meal (address and port) at once. */ 
                dbg_err_if (u_strlcpy(authority, ap, sizeof authority));
            }
            else
            {
                dbg_err_if (u_strlcpy(host, evcoap_opt_get_string_pretty(opt), 
                            sizeof host));
            }
        }

        /* Give precedence to authority, in case it was set by the Uri-Host
         * handler. */
        if (opt->sym >= EVCOAP_OPT_URI_PORT
                && port[0] == '\0' 
                && authority[0] == '\0')
        {
            ev_uint64_t p;
            const struct sockaddr *sa = (const struct sockaddr *) &pdu->me;
            const struct sockaddr_in6 *s6;
            const struct sockaddr_in *s4;

            /* "[...] the default value of the Uri-Port Option is the 
             *  destination UDP port." */
            if (opt->sym != EVCOAP_OPT_URI_PORT)
            {
                /* Note: I don't get the meaning of an explicit Uri-Port. 
                 * How could it be different from the port on which we 
                 * received the PDU ? */
                switch (sa->sa_family)
                {
                    case AF_INET6:
                        s6 = (const struct sockaddr_in6 *) sa;
                        p = ntohs(s6->sin6_port);
                        break;
                    case AF_INET:
                        s4 = (const struct sockaddr_in *) sa;
                        p = ntohs(s4->sin_port);
                        break;
                    default:
                        dbg_err("Unsupported address family");
                }
            }
            else
                dbg_err_if (evcoap_opt_get_uint_pretty(opt, &p));

            dbg_err_if (u_snprintf(port, sizeof port, "%llu", p));
        }

        if (opt->sym == EVCOAP_OPT_URI_PATH)
        {
            dbg_err_if (u_strlcat(path, "/", sizeof path));
            dbg_err_if (u_strlcat(path, evcoap_opt_get_string_pretty(opt),
                        sizeof path));
        }

        if (opt->sym == EVCOAP_OPT_URI_QUERY)
        {
            dbg_err_if (u_strlcat(query, (query[0] == '\0') ? "?" : "&",
                        sizeof query));
            dbg_err_if (u_strlcat(query, evcoap_opt_get_string_pretty(opt),
                        sizeof query));
        }
    }

    /* Assemble the URI from tokens. */
    dbg_err_if (u_uri_new(0, &u));

    (void) u_uri_set_scheme(u, pdu->secure ? "coaps" : "coap");
    if (authority[0] == '\0')
    {
        (void) u_uri_set_host(u, host);
        (void) u_uri_set_port(u, port);
    }
    else
        (void) u_uri_set_authority(u, authority);

    (void) u_uri_set_path(u, path[0] == '\0' ? "/" : path);

    if (query[0] != '\0')
        (void) u_uri_set_query(u, query);

    pdu->uri = u;

    return 0;
err:
    if (u)
        u_uri_free(u);
    return -1;
}

int evcoap_pdu_uri_compose(struct evcoap_pdu *pdu)
{
    if (evcoap_pdu_uri_compose_proxy(pdu) == 0
            || evcoap_pdu_uri_compose_tokens(pdu) == 0)
        return 0;
    return -1;
}

struct evcoap_opt *evcoap_opt_get(struct evcoap_pdu *pdu, evcoap_opt_t sym)
{
    return evcoap_opt_get_nth(pdu, sym, 0);
}

struct evcoap_opt *evcoap_opt_get_nth(struct evcoap_pdu *pdu, evcoap_opt_t sym, 
        size_t n)
{
    struct evcoap_opt *o;

    TAILQ_FOREACH(o, &pdu->options, next)
    {
        if (o->sym == sym)
        {
            if (n == 0)
                return o;
            --n;
        }
    }

    return NULL;
}

/* Map internal representation of the supplied option to its corresponding
 * protocol code. */
size_t evcoap_opt_sym2num(evcoap_opt_t sym)
{
    dbg_return_if (!EVCOAP_OPT_SYM_VALID(sym), EVCOAP_OPT_NONE);

    return g_opts[sym].n;
}

/* Map Option protocol code to its internal representation. */
evcoap_opt_t evcoap_opt_num2sym(size_t num)
{
    size_t i;

    for (i = 0; i < EVCOAP_OPTS_MAX; ++i)
    {
        if (num == g_opts[i].n)
            return (evcoap_opt_t) i;
    }

    u_dbg("Option with number %zu could not be resolved", num);

    return EVCOAP_OPT_NONE;
}

const char *evcoap_opt_sym2str(evcoap_opt_t sym)
{
    dbg_return_if (!EVCOAP_OPT_SYM_VALID(sym), "Out-of-bounds");

    return g_opts[sym].s;
}

evcoap_opt_type_t evcoap_opt_sym2type(evcoap_opt_t sym)
{
    dbg_return_if (!EVCOAP_OPT_SYM_VALID(sym), EVCOAP_OPT_TYPE_INVALID);

    return g_opts[sym].t;
}

int evcoap_opt_add_uint(struct evcoap_pdu *pdu, evcoap_opt_t sym, 
        ev_uint64_t v)
{
    ev_uint8_t e[8];
    size_t elen = sizeof e;

    dbg_return_if (evcoap_opt_sym2type(sym) != EVCOAP_OPT_TYPE_UINT, -1);
    dbg_return_if (evcoap_opt_encode_uint(v, e, &elen), -1);

    return evcoap_opt_add_raw(pdu, sym, e, elen);
}

int evcoap_opt_add_string(struct evcoap_pdu *pdu, evcoap_opt_t sym, 
        const char *s)
{
    dbg_return_if (evcoap_opt_sym2type(sym) != EVCOAP_OPT_TYPE_STRING, -1);

    return evcoap_opt_add_raw(pdu, sym, (ev_uint8_t *) s, strlen(s));
}

int evcoap_opt_add_opaque(struct evcoap_pdu *pdu, evcoap_opt_t sym, 
        const ev_uint8_t *v,  size_t l)
{
    dbg_return_if (evcoap_opt_sym2type(sym) != EVCOAP_OPT_TYPE_OPAQUE, -1);

    return evcoap_opt_add_raw(pdu, sym, v, l);
}

int evcoap_opt_add_empty(struct evcoap_pdu *pdu, evcoap_opt_t sym)
{
    dbg_return_if (evcoap_opt_sym2type(sym) != EVCOAP_OPT_TYPE_EMPTY, -1);

    return evcoap_opt_add_raw(pdu, sym, NULL, 0);
}

/* 'v' is the complete value, which will be fragmented in one or more option 
 * slots if needed. */
int evcoap_opt_add_raw(struct evcoap_pdu *pdu, evcoap_opt_t sym,
        const ev_uint8_t *v,  size_t l)
{
    size_t nseg, offset = 0,
           full_seg_no = l / EVCOAP_OPT_LEN_MAX,
           rem = l % EVCOAP_OPT_LEN_MAX,
           to_be_used_opts = (full_seg_no + ((rem || !l) ? 1 : 0));

    /* First off, check if we have enough slots available
     * to encode the supplied option. */
    dbg_err_ifm (pdu->noptions + to_be_used_opts > COAP_OPTIONS_MAX,
            "not enough slots available to encode option");

    /* Handle option fragmentation. */
    for (nseg = 0; nseg < full_seg_no; nseg++)
    {
        dbg_err_if (evcoap_opt_add(pdu, sym, v + offset, EVCOAP_OPT_LEN_MAX));

        /* Shift offset to point next fragment. */
        offset = nseg * EVCOAP_OPT_LEN_MAX;
    }

    /* Take care of the "remainder" slot (or an empty option.)
     * (TODO check that option is allowed to be zero length?) */
    if (rem || !l)
    {
        dbg_err_if (evcoap_opt_add(pdu, sym, v + offset, !l ? 0 : rem));
    }

    return 0;
err:
    return -1;
}

int evcoap_opt_add(struct evcoap_pdu *pdu, evcoap_opt_t sym, 
        const ev_uint8_t *v, size_t l)
{
    struct evcoap_opt *opt = NULL;

    dbg_err_if ((opt = evcoap_opt_new_empty()) == NULL);
    dbg_err_if (evcoap_opt_set(opt, sym, v, l));
    dbg_err_if (evcoap_opt_push(pdu, opt));
    opt = NULL;

    return 0;
err:
    evcoap_opt_free(opt);
    return -1;
}

int evcoap_opt_parse(struct evcoap_pdu *pdu)
{
    ev_uint8_t opt_len, skip_this;
    size_t opt_num = 0;
    unsigned int opt_count;
    struct evcoap_opt *opt = NULL;
    ev_uint8_t *opt_p = pdu->data + EVCOAP_PDU_HDR_LEN;    /* Skip header. */

    /* Trust the caller. */

    for (opt_count = pdu->oc; opt_count > 0; opt_count--)
    {
        /* A priori, all options are equal.  While processing them, though,
         * we'll discover that some are more equal than others (unrecognized
         * elective options and fence-posts will assert this flag.) */
        skip_this = 0;

        /* Read delta and deduce option number. */ 
        opt_num += (*opt_p >> 4);

        switch (opt_num)
        {
            case EVCOAP_OPT_PROXY_URI:
            case EVCOAP_OPT_CONTENT_TYPE:
            case EVCOAP_OPT_MAX_AGE:
            case EVCOAP_OPT_ETAG:
            case EVCOAP_OPT_URI_HOST:
            case EVCOAP_OPT_LOCATION_PATH:
            case EVCOAP_OPT_URI_PORT:
            case EVCOAP_OPT_LOCATION_QUERY:
            case EVCOAP_OPT_URI_PATH:
            case EVCOAP_OPT_OBSERVE:
            case EVCOAP_OPT_TOKEN:
            case EVCOAP_OPT_ACCEPT:
            case EVCOAP_OPT_IF_MATCH:
            case EVCOAP_OPT_MAX_OFE:
            case EVCOAP_OPT_URI_QUERY:
            case EVCOAP_OPT_IF_NONE_MATCH:
                break;
            default:
                /* Unrecognized options of class "critical" that occur in 
                 * a confirmable request MUST cause the return of a 4.02 
                 * (Bad Option) response.  This response SHOULD include a 
                 * human-readable error message describing the unrecognized
                 * option(s). */
                if (opt_num % 2) /* Even option number == critical. */
                {
                    /* TODO */
                    dbg_err_ifm(1, "unknown CoAP Option %zu", opt_num);
                }
                else
                {
                    skip_this = 1;
                    break;
                }
        }

        /* Read length (base or extended.) */
        if ((opt_len = (*opt_p & 0x0f)) == 0x0f)
            opt_len = *(opt_p + 1) + 15;

        /* Jump over the lenght indicators to get to the option value. */
        opt_p += ((opt_len > 15) ? 2 : 1);

        /* Extract option and add it to the pool. */
        if (!skip_this)
        {
            dbg_err_if ((opt = evcoap_opt_new_empty()) == NULL);

            /* Get option value. */
            dbg_err_if (evcoap_opt_set(opt, evcoap_opt_num2sym(opt_num), 
                        opt_p, opt_len));

            /* Add to the currently processed message. */
            dbg_err_if (evcoap_opt_push(pdu, opt));
            opt = NULL;
        }

        /* Jump over this option's value and come again. */
        opt_p += opt_len;
    }

    /* Set payload offset. */
    pdu->payload = opt_p;

    return 0;
err:
    evcoap_opt_free(opt);
    return -1;
}

int evcoap_opt_push(struct evcoap_pdu *pdu, struct evcoap_opt *opt)
{
    struct evcoap_opt *tmp;

    dbg_return_if (pdu->noptions == COAP_OPTIONS_MAX, -1);

    /* 
     * Ordered (lo[0]..hi[n]) insertion of new elements.
     */

    /* Empty. */
    if (TAILQ_EMPTY(&pdu->options))
    {
        TAILQ_INSERT_TAIL(&pdu->options, opt, next);
        goto end;
    }

    /* Not the lowest. */
    TAILQ_FOREACH_REVERSE(tmp, &pdu->options, evcoap_opts, next)
    {
        if (opt->sym >= tmp->sym)
        {
            TAILQ_INSERT_AFTER(&pdu->options, tmp, opt, next);
            goto end;
        }
    }

    /* Lowest. */
    TAILQ_INSERT_HEAD(&pdu->options, opt, next);

    /* Fall through. */
end:
    pdu->noptions += 1;
    return 0;
}

struct evcoap_opt *evcoap_opt_new_empty(void)
{
    struct evcoap_opt *opt = NULL;

    dbg_return_sif ((opt = u_malloc(sizeof *opt)) == NULL, NULL);

    opt->sym = EVCOAP_OPT_NONE;
    opt->t = EVCOAP_OPT_TYPE_INVALID;
    opt->l = 0;
    opt->v = NULL;

    return opt;
}

void evcoap_opt_free(struct evcoap_opt *opt)
{
    if (opt)
    {
        u_free(opt->v);
        u_free(opt);
    }
    return;
}

int evcoap_opt_decode_uint(const ev_uint8_t *ui, size_t len, 
        ev_uint64_t *pui)
{
    size_t i;

    dbg_return_if (len > sizeof(ev_uint64_t), -1);

    *pui = 0;

    /* Trust the caller. */

    /* XXX Assume LE host. */
    /* TODO BE host (nop). */
    for (i = len; i > 0; i--)
        *pui |= (ui[i - 1] << (8 * (len - i)));

    return 0;
}

/* 'elen' is value-result argument.  It MUST be initially set to the size
 * of 'e'.  On a successful return it will hold the lenght of the encoded 
 * uint (i.e. # of valid bytes in 'e'.) */
int evcoap_opt_encode_uint(ev_uint64_t ui, ev_uint8_t *e, size_t *elen)
{
    size_t i, j;

    ev_uint64_t ui_bytes[] =
    {
        (1ULL <<  8) - 1,
        (1ULL << 16) - 1, 
        (1ULL << 24) - 1,
        (1ULL << 32) - 1,
        (1ULL << 40) - 1,
        (1ULL << 48) - 1, 
        (1ULL << 56) - 1,
        UINT64_MAX
    };

    /* Pick size. */
    for (i = 0; i < (sizeof ui_bytes / sizeof(ev_uint64_t)); i++)
        if (ui_bytes[i] > ui)
            break;

    dbg_err_ifm (*elen < i + 1, "not enough bytes for encoding %llu", ui);

    /* XXX Assume LE host. */
    /* TODO BE host (nop). */
    for (j = 0; j <= i; ++j)
        e[j] = (ui >> (8 * j)) & 0xff;

    *elen = i + 1;

    return 0;
err:
    return -1;
}

int evcoap_opt_set(struct evcoap_opt *opt, evcoap_opt_t sym,
        const ev_uint8_t *val, size_t len)
{
    size_t vlen;

    /* TODO check that option number is valid. */

    opt->sym = sym;

    switch ((opt->t = evcoap_opt_sym2type(sym)))
    {
        case EVCOAP_OPT_TYPE_INVALID:
            u_dbg("Invalid option type !  Failed option (%s)",
                    evcoap_opt_sym2str(sym));
            return -1;
        case EVCOAP_OPT_TYPE_EMPTY:
            /* Empty options have no value, so they stop here. */
            opt->v = NULL;
            opt->l = 0;
            return 0;
        default:
            break;
    }

    dbg_return_if ((opt->l = len) > EVCOAP_OPT_LEN_MAX, -1);

    /* Make room for the option value. */
    vlen = (opt->t != EVCOAP_OPT_TYPE_STRING) ? opt->l : opt->l + 1;
    dbg_return_sif ((opt->v = u_malloc(vlen)) == NULL, -1);
    memcpy(opt->v, val, opt->l);

    /* Be C friendly: NUL-terminate in case it's a string. */
    if (opt->t == EVCOAP_OPT_TYPE_STRING)
        opt->v[vlen - 1] = '\0';

    return 0;
}

struct evcoap_rcvd_pdu *evcoap_rcvd_pdu_new(ev_uint16_t mid, 
        struct timeval *when, const struct sockaddr_storage *ss, 
        ev_socklen_t ss_len)
{
    struct evcoap_rcvd_pdu *new = NULL;

    dbg_return_sif ((new = u_malloc(sizeof *new)) == NULL, NULL);

    new->when = *when;
    new->mid = mid;
    memcpy(&new->ss, ss, ss_len);
    new->ss_len = ss_len;
    new->sent_pdu = NULL;
    new->sent_pdu_len = 0;

    return new;
}

void evcoap_rcvd_pdu_free(struct evcoap_rcvd_pdu *rcvd)
{
    if (rcvd)
    {
        u_free(rcvd->sent_pdu);
        u_free(rcvd); 
    }

    return;
}

int evcoap_pdu_dup_handler(struct evcoap *coap, int sd, ev_uint16_t mid,
        const struct sockaddr_storage *ss, ev_socklen_t ss_len)
{
    struct timeval tv;
    struct evcoap_rcvd_pdu *rcvd;

    TAILQ_FOREACH (rcvd, &coap->rcvd_queue, next)
    {
        /* Check if the same MID was seen from the same sender. */
        if (rcvd->mid == mid
                && !evutil_sockaddr_cmp((const struct sockaddr *) &rcvd->ss,
                    (const struct sockaddr *) ss, ss_len))
        {
            /* "The recipient SHOULD acknowledge each duplicate copy of a 
             *  confirmable message using the same acknowledgement or reset 
             *  message, but SHOULD process any request or response in the 
             *  message only once. [...] the recipient SHOULD silently ignore 
             *  any duplicated non-confirmable message, and SHOULD process any 
             *  request or response in the message only once" */
            if (rcvd->sent_pdu)
            {
                if (sendto(sd, rcvd->sent_pdu, rcvd->sent_pdu_len, 0,
                            (const struct sockaddr *) ss, ss_len) == -1)
                {
                    int e = evutil_socket_geterror(sd);
                    u_dbg("%s", evutil_socket_error_to_string(e));
                }
            }

            return -1;
        }
    }

    /* Not a dup: insert it in the received PDUs queue. */
    /* XXX creation error should get a distinct return code from !found. */
    dbg_err_if (event_base_gettimeofday_cached(coap->base, &tv));
    dbg_err_if ((rcvd = evcoap_rcvd_pdu_new(mid, &tv, ss, ss_len)) == NULL);
    TAILQ_INSERT_TAIL(&coap->rcvd_queue, rcvd, next);

    return 0;
err:
    return -1;
}

struct evcoap_pdu *evcoap_pdu_new_empty(void)
{
    struct evcoap_pdu *pdu = NULL;

    dbg_return_sif ((pdu = u_malloc(sizeof(struct evcoap_pdu))) == NULL, NULL);

    TAILQ_INIT(&pdu->options);
    pdu->noptions = 0;

    /* TODO Add protocol version. */
    pdu->mid = 0;

    pdu->method = EVCOAP_METHOD_UNSET;
    pdu->msg_type = EVCOAP_MSG_TYPE_UNSET;
    pdu->rcode = EVCOAP_RESP_CODE_UNSET;

    pdu->data = NULL;
    pdu->datalen = 0;
    pdu->payload = NULL;
    pdu->payload_len = 0;

    pdu->uri = NULL;
    pdu->sd = -1;
    pdu->secure = 0;
    pdu->send_status = EVCOAP_SEND_STATUS_OK;
    pdu->gai_req = NULL;

    pdu->peer_len = pdu->me_len = 0;
    memset(&pdu->peer, 0, sizeof pdu->peer);
    memset(&pdu->me, 0, sizeof pdu->me);

    return pdu;
}

struct evcoap_pdu *evcoap_pdu_new_received(struct evcoap *coap, int sd,
        const ev_uint8_t *d, size_t dlen, ev_uint8_t secure,
        const struct sockaddr_storage *peer, const ev_socklen_t peer_len)
{
    ev_uint16_t mid;
    struct evcoap_pdu *pdu = NULL;

    /* TTC */

    /* 
     * Check that at least a full header is present.
     */
    dbg_return_ifm (dlen < EVCOAP_PDU_HDR_LEN, NULL, 
            "not enough bytes to hold a CoAP header");

    /* 
     * Do early duplicate detection.
     */
    mid = ntohs((d[2] << 8) | d[3]);
    dbg_err_ifm (evcoap_pdu_dup_handler(coap, sd, mid, peer, peer_len),
            "Duplicate PDU detected (MID=%u)", mid);

    /* 
     * Make room for the new PDU.
     *
     * XXX This malloc could be posticipated after header has been fully
     * XXX sanity checked. */
    dbg_err_sif ((pdu = evcoap_pdu_new_empty()) == NULL);

    /* 
     * Complete header parsing, and check its consistency (WIP).
     */
    pdu->t = (d[0] & 0x30) >> 4;
    pdu->oc = d[0] & 0x0f;
    pdu->code = d[1];
    pdu->mid = mid;
    dbg_err_ifm ((pdu->ver = (d[0] & 0xc0) >> 6) != COAP_PROTO_VER_1,
            "Unsupported CoAP version %u", pdu->ver);

    /*
     * Decode message type and method or response code.
     */
    switch ((pdu->msg_type = evcoap_pdu_decode_type(pdu->code)))
    {
        case EVCOAP_MSG_TYPE_EMPTY:
            dbg_err_ifm (dlen, "non void payload in packet of type empty");
            break;
        case EVCOAP_MSG_TYPE_REQ:
            dbg_err_ifm (evcoap_pdu_decode_method(pdu->code, &pdu->method),
                    "Method decoding failed");
            break;
        case EVCOAP_MSG_TYPE_RESP:
            dbg_err_ifm (evcoap_pdu_decode_resp_code(pdu->code, &pdu->rcode),
                    "Response code decoding failed");
            break;
        default:
            dbg_err("CoAP message uses reserved code (%u)", pdu->code);
    }

    /* 
     * Copy in raw packet (if non-empty.)
     */
    if ((pdu->datalen = dlen))
    {
        dbg_err_sif ((pdu->data = u_memdup(d, dlen)) == NULL);
    }

    /* 
     * Save addressing info and socket descriptor.
     */
    pdu->sd = sd;
    memcpy(&pdu->peer, peer, peer_len);
    pdu->peer_len = peer_len;
    pdu->me_len = sizeof pdu->me;
    dbg_err_sif (getsockname(sd,
                (struct sockaddr *) &pdu->me, &pdu->me_len) == -1);

    /* 
     * Parse options, if any (also set the payload offset pointer.)
     */
    if (pdu->oc)
        dbg_err_ifm (evcoap_opt_parse(pdu), "could not parse options");

    /* 
     * Set DTLS flag.  This MUST be done before the URI is reassembled
     * to decide for 'coap' vs 'coaps' scheme.
     */
    pdu->secure = secure;

    /* 
     * Reassemble URI (if applicable) from options.
     */
    dbg_err_if (evcoap_pdu_uri_compose(pdu));

    {
        char url[U_URI_STRMAX] = { '\0' };
        (void) u_uri_knead(pdu->uri, url);
        EVCOAP_TRACE("CoAP packet:\n" 
                "\thdr { ver=%u, t=%s, oc=%u, code=%u, mid=%u }\n"
                "\ttype=%s, method=%s\n"
                "\turl=%s\n",
                pdu->ver, evcoap_pdu_types[pdu->t], pdu->oc, pdu->code, 
                pdu->mid, evcoap_msg_types[pdu->msg_type], 
                evcoap_methods[pdu->method], *url ? url : "-");
    }

    return pdu;
err:
    if (pdu)
        evcoap_pdu_free(pdu);
    return NULL;
}

evcoap_msg_type_t evcoap_pdu_decode_type(ev_uint8_t code)
{
    if (code == 0)
        return EVCOAP_MSG_TYPE_EMPTY;
    else if (code > 0 && code < 32)
        return EVCOAP_MSG_TYPE_REQ;
    else if (code > 63 && code < 192)
        return EVCOAP_MSG_TYPE_RESP;
         
    return EVCOAP_MSG_TYPE_RESERVED;
}

int evcoap_pdu_decode_resp_code(ev_uint8_t code, evcoap_resp_code_t *pc)
{
    /* Trust the caller. */

    if (code & 0x40)        /* 2.xx */
    {
        switch ((*pc = code))
        {
            case EVCOAP_RESP_CODE_CREATED:
            case EVCOAP_RESP_CODE_DELETED:
            case EVCOAP_RESP_CODE_VALID:
            case EVCOAP_RESP_CODE_CHANGED:
            case EVCOAP_RESP_CODE_CONTENT:
                break;
            default:
                u_dbg("Unknown 2.xx response code %u", code);
                *pc = EVCOAP_RESP_CODE_200_UNKNOWN;
                /* Fall through. */
        }

        return 0;
    }
    else if (code & 0x80)   /* 4.xx */
    {
        switch ((*pc = code))
        {
            case EVCOAP_RESP_CODE_BAD_REQUEST:
            case EVCOAP_RESP_CODE_UNAUTHORIZED:
            case EVCOAP_RESP_CODE_BAD_OPTION:
            case EVCOAP_RESP_CODE_FORBIDDEN:
            case EVCOAP_RESP_CODE_NOT_FOUND:
            case EVCOAP_RESP_CODE_METHOD_NOT_ALLOWED:
            case EVCOAP_RESP_CODE_NOT_ACCEPTABLE:
            case EVCOAP_RESP_CODE_PRECONDITION_FAILED:
            case EVCOAP_RESP_CODE_REQUEST_ENTITY_TOO_LARGE:
            case EVCOAP_RESP_CODE_UNSUPPORTED_MEDIA_TYPE:
                break;
            default:
                u_dbg("Unknown 4.xx response code %u", code);
                *pc = EVCOAP_RESP_CODE_400_UNKNOWN;
                /* Fall through. */
        }

        return 0;
    }
    else if (code & 0xa0)   /* 5.xx */
    {
        switch ((*pc = code))
        {
            case EVCOAP_RESP_CODE_INTERNAL_SERVER_ERROR:
            case EVCOAP_RESP_CODE_NOT_IMPLEMENTED:
            case EVCOAP_RESP_CODE_BAD_GATEWAY:
            case EVCOAP_RESP_CODE_SERVICE_UNAVAILABLE:
            case EVCOAP_RESP_CODE_GATEWAY_TIMEOUT:
            case EVCOAP_RESP_CODE_PROXYING_NOT_SUPPORTED:
                break;
            default:
                u_dbg("Unknown 5.xx response code %u", code);
                *pc = EVCOAP_RESP_CODE_500_UNKNOWN;
                /* Fall through. */
        }

        return 0;
    }

    u_dbg("Unknown response code %u", code);
    return -1;
}

int evcoap_pdu_decode_method(ev_uint8_t code, evcoap_method_t *pm)
{
    /* Trust the caller. */

    /* Assign and validate method. */
    switch ((*pm = code))
    {
        case EVCOAP_METHOD_GET:
        case EVCOAP_METHOD_POST:
        case EVCOAP_METHOD_PUT:
        case EVCOAP_METHOD_DELETE:
            return 0;
        default:
            break;
    }

    u_dbg("Unknown CoAP method (%u)", code);
    return -1;
}

void evcoap_pdu_free(struct evcoap_pdu *pdu)
{
    if (pdu)
    {
        u_free(pdu->data);
        u_uri_free(pdu->uri);
        /* TODO free options. */
        /* TODO free payload if malloc'd */
        u_free(pdu);
    }

    return;
}

struct evcoap_bound_socket *evcoap_bound_socket_new(struct evcoap *coap,
        evutil_socket_t sd, ev_uint8_t secure)
{
    struct evcoap_bound_socket *bs = NULL;

    /* Trust the caller (no param sanitization.) */

    dbg_err_sif ((bs = u_malloc(sizeof(struct evcoap_bound_socket))) == NULL);

    /* Create a new (persistent) read event in the base for the supplied
     * socket descriptor. */
    dbg_err_if ((bs->ev = event_new(coap->base, sd, EV_READ | EV_PERSIST,
                    evcoap_input, coap)) == NULL);
    bs->sd = sd;
    bs->secure = secure;

    /* Make the read event pending in the base. */
    dbg_err_if (event_add(bs->ev, NULL) == -1);

    return bs;
err:
    evcoap_bound_socket_free(bs);
    return NULL;
}

const char *evcoap_pdu_get_string_opt(struct evcoap_pdu *pdu, evcoap_opt_t sym)
{
    struct evcoap_opt *opt;

    dbg_err_if (pdu == NULL);

    if ((opt = evcoap_opt_get(pdu, sym)) == NULL)
        goto err;

    return evcoap_opt_get_string_pretty(opt);
err:
    return NULL;
}

int evcoap_pdu_get_uint_opt(struct evcoap_pdu *pdu, evcoap_opt_t sym, 
        ev_uint64_t *pui)
{
    struct evcoap_opt *opt;

    dbg_err_if (pdu == NULL);

    if ((opt = evcoap_opt_get(pdu, sym)) == NULL)
        goto err;

    dbg_err_if (evcoap_opt_get_uint_pretty(opt, pui));

    return 0;
err:
    return -1;
}

const char *evcoap_opt_get_string_pretty(struct evcoap_opt *opt)
{
    dbg_return_if (opt->t != EVCOAP_OPT_TYPE_STRING, NULL);

    /* Assume that the setter has NUL-terminated the value buffer. */
    return (const char *) opt->v;
}

int evcoap_opt_get_uint_pretty(struct evcoap_opt *opt, ev_uint64_t *pui)
{
    dbg_return_if (opt->t != EVCOAP_OPT_TYPE_UINT, -1);

    return evcoap_opt_decode_uint(opt->v, opt->l, pui);
}

void evcoap_bound_socket_free(struct evcoap_bound_socket *bs)
{
    if (bs)
    {
        if (bs->ev)
           event_free(bs->ev); 
        u_free(bs);
    }
    return;
}

/* sizeof b must be at least EVCOAP_OPTS_UPPER_LEN. */
int evcoap_opts_encode(struct evcoap_pdu *pdu, ev_uint8_t *b, size_t *plen)
{
    ev_uint8_t *p = b;
    struct evcoap_opt *opt;
    size_t cur, last = 0, delta, left, elen;

    dbg_return_if ((left = *plen) < EVCOAP_OPTS_UPPER_LEN, -1);

    /* Assume options are already ordered from lowest to highest. */
    TAILQ_FOREACH(opt, &pdu->options, next)
    {
        u_dbg("Processing %s", evcoap_opt_sym2str(opt->sym));

        /* Pop next option and process it. */
        dbg_ifb ((cur = evcoap_opt_sym2num(opt->sym)) == EVCOAP_OPT_NONE)
            continue;

        /* Compute how much space we're going to consume, so that we don't
         * have to check at each encode step. */
        elen = ((opt->l > 14) ? 2 : 1) + opt->l;

        dbg_err_ifm (elen > left,
                "Not enough space (%zu vs %zu) to encode %s",
                elen, left, evcoap_opt_sym2str(opt->sym));

        /* Delta encode the option number. */
        dbg_err_if ((delta = cur - last) > 14);
#ifdef TODO
        /* Insert the needed fenceposts. */
        dbg_err_if (!(p = evcoap_opt_add_fenceposts(p, &left, cur, delta)));
#endif
        /* Encode length. */
        if (opt->l > 14)
        {
            *p++ = (delta << 4) | 0x0f;
            *p++ = opt->l - 15;
        }
        else
        {
            *p++ = (delta << 4) | (opt->l & 0x0f);
        }

        /* Put value. */
        if (opt->v)
        {
            memcpy(p, opt->v, opt->l);
            p += opt->l;
        }

        /* Decrement available bytes. */
        left -= elen;

        /* Update state for delta computation. */
        last = cur;
    }

    pdu->oc = pdu->noptions;    /* XXX Should take care of fenceposts. */

    *plen -= left;

    evcoap_dbg_print_buffer("options", b, *plen);

    return 0;
err:
    return -1;
}

#ifdef TODO
/* Insert the needed fenceposts in case option delta is a multiple of 14. */
ev_uint8_t *evcoap_opt_add_fenceposts(ev_uint8_t *opt_p, size_t *pleft, 
        size_t num, size_t delta)
{
    size_t i;

    for (i = 1; i < 15; i++)
    {
        if (i * 14 < delta)
        {
            /* Insert fencepost. */

        }   
    }

    return opt_p;
}
#endif  /* TODO */

int evcoap_pdu_sanitize_send_req(struct evcoap *coap, struct evcoap_pdu *pdu)
{
    dbg_return_if (pdu == NULL, -1);

    /* Assert Confirmable or Non-Confirmable. */
    dbg_return_if (pdu->t != EVCOAP_PDU_TYPE_CON
            && pdu->t != EVCOAP_PDU_TYPE_NON, -1);

    /* Assert a valid method. */
    dbg_return_if (!EVCOAP_METHOD_VALID(pdu->code), -1);

    /* If MID is not already set, generate one. */
    if (!pdu->mid)
        evutil_secure_rng_get_bytes(&pdu->mid, sizeof pdu->mid);

    /* Force CoAP version. */
    pdu->ver = COAP_PROTO_VER_1;

    /* Align internal maps. */
    pdu->msg_type = EVCOAP_MSG_TYPE_REQ;
    pdu->method = pdu->t;
    pdu->rcode = EVCOAP_RESP_CODE_UNSET;

    /* Check that a destination URI was set. */
    /* dbg_return_if (pdu->uri == NULL, -1); */
    /* URI is set in options. */

    return 0;
}

int evcoap_do_send_request(struct evcoap *coap, struct evcoap_pdu *pdu,
        void (*cb)(struct evcoap_pdu *, int, void *), void *cb_args,
        struct timeval *timeout)
{
    return -1;
}

void evcoap_sendreq_dns_cb(int result, struct evutil_addrinfo *res, void *a)
{
    struct evutil_addrinfo *ai;
    ev_uint8_t hdr[4], opts[EVCOAP_OPTS_UPPER_LEN];
    size_t opts_len = sizeof opts;
    struct evcoap_sendreq_args *sendreq_args;
    struct evcoap_pdu *pdu;
    struct evcoap *coap;
    void (*cb)(struct evcoap_pdu *, int, void *);
    void *cb_args;
    struct evcoap_opt *t;

    /* Unroll arguments. */
    sendreq_args = (struct evcoap_sendreq_args *) a;
    pdu = sendreq_args->pdu;
    coap = sendreq_args->coap;
    cb = sendreq_args->cb;
    cb_args = sendreq_args->cb_args;

    /* Unset the evdns_getaddrinfo_request pointer, since when we get called
     * its lifetime is exhausted. */
    pdu->gai_req = NULL;

    /* Early return on DNS failures. */
    if (result != DNS_ERR_NONE)
    {
        u_dbg("DNS resolution failed for %s: %s", 
                u_uri_get_host(pdu->uri), 
                evutil_gai_strerror(result));
        pdu->send_status = EVCOAP_SEND_STATUS_DNS_FAIL;
        goto err;
    }

    /* Since the supplied host (and service name) resolved successfully, 
     * we have some non-null chance to deliver the request to something/someone
     * out there.  First off encode options and header. */
    dbg_err_if (evcoap_opts_encode(pdu, opts, &opts_len));
    evcoap_build_header(pdu->ver, pdu->t, pdu->oc, pdu->code, pdu->mid, hdr);

    /* Then for each returned sockaddr, try to push the request across the
     * network. */
    for (pdu->sd = -1, ai = res; ai; ai = ai->ai_next)
    {
        pdu->sd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (pdu->sd == -1)
            continue;

        /* Call PDU sender. */
        if (evcoap_send(coap, pdu->sd, 
                (const struct sockaddr_storage *) ai->ai_addr,
                ai->ai_addrlen, hdr, opts, opts_len, pdu->payload,
                pdu->payload_len))
        {
            pdu->sd = -1;   /* Mark socket as failed and try again. */
            continue;
        }

        /* If raw UDP send was ok. save the Token into the outstanding 
         * requests set. */
        dbg_err_if ((t = evcoap_opt_get(pdu, EVCOAP_OPT_TOKEN)) == NULL);
        dbg_err_if (evcoap_pending_token_add(coap, cb, cb_args, t->v, t->l));

        /* Also, in case it is a CON message, save the outstanding MID for
         * ACK/RST matching. */
        if (pdu->t == EVCOAP_PDU_TYPE_CON)
            dbg_err_if (evcoap_pending_mid_add(coap, cb, cb_args, pdu->mid));
    }

    dbg_err_if (pdu->sd == -1);
    pdu->send_status = EVCOAP_SEND_STATUS_OK;
    evcoap_sendreq_args_free(sendreq_args);
    return;

err:
    pdu->send_status = EVCOAP_SEND_STATUS_ERR;
    evcoap_sendreq_args_free(sendreq_args);
    return;
}

int evcoap_pending_token_add(struct evcoap *coap,
       void (*cb)(struct evcoap_pdu *, int, void *), void *cb_args,
       ev_uint8_t *token, size_t token_len)
{
    /* TODO */
    return 0;
}

int evcoap_pending_mid_add(struct evcoap *coap,
       void (*cb)(struct evcoap_pdu *, int, void *), void *cb_args,
       ev_uint16_t mid)
{
    /* TODO */
    return 0;
}

struct evcoap_sendreq_args *evcoap_sendreq_args_new(struct evcoap *coap, 
        struct evcoap_pdu *pdu, void (*cb)(struct evcoap_pdu *, int, void *),
        void *cb_args, struct timeval *timeout)
{
    struct evcoap_sendreq_args *sendreq_args = u_malloc(sizeof(*sendreq_args));

    if (sendreq_args)
    {
        sendreq_args->coap = coap;
        sendreq_args->pdu = pdu;
        sendreq_args->cb = cb;
        sendreq_args->cb_args = cb_args;
        sendreq_args->timeout = timeout;
    }

    return sendreq_args;
}

void evcoap_sendreq_args_free(struct evcoap_sendreq_args *sendreq_args)
{
    u_free(sendreq_args);
    return;
}
