#ifndef _EVCOAP_PRIV_H_
#define _EVCOAP_PRIV_H_

#include <u/libu.h>
#include <event2/event.h>

/* TODO sub 1 with trace flag. */
#define EVCOAP_TRACE(...) do { if (1) u_con(__VA_ARGS__); } while(0)

/* At present we depend on libu for URI manipulation.
 * This may change in the future if we decide to reuse
 * libevent HTTP URI handling facilities. */
#define EVCOAP_URI_MAX  U_URI_STRMAX

/* CoAP message codes get de-synthesized in: EVCOAP_MSG_TYPE and EVCOAP_METHOD
 * or EVCOAP_RESP_CODE. */
typedef enum 
{
    EVCOAP_MSG_TYPE_EMPTY    = 0,
    EVCOAP_MSG_TYPE_REQ      = 1,
    EVCOAP_MSG_TYPE_RESP     = 2,
    EVCOAP_MSG_TYPE_RESERVED = 3,
    EVCOAP_MSG_TYPE_UNSET    = 4
} evcoap_msg_type_t;
#define EVCOAP_MSG_TYPE_VALID(t)    ((t) <= EVCOAP_MSG_TYPE_RESP)

typedef enum 
{
    EVCOAP_OPT_NONE = 0,

    EVCOAP_OPT_CONTENT_TYPE,
    EVCOAP_OPT_MAX_AGE,
    EVCOAP_OPT_PROXY_URI,
    EVCOAP_OPT_ETAG,
    EVCOAP_OPT_URI_HOST,
    EVCOAP_OPT_LOCATION_PATH,
    EVCOAP_OPT_URI_PORT,
    EVCOAP_OPT_LOCATION_QUERY,
    EVCOAP_OPT_URI_PATH,
    EVCOAP_OPT_OBSERVE,
    EVCOAP_OPT_TOKEN,
    EVCOAP_OPT_ACCEPT,
    EVCOAP_OPT_IF_MATCH,
    EVCOAP_OPT_MAX_OFE,
    EVCOAP_OPT_URI_QUERY,
    EVCOAP_OPT_IF_NONE_MATCH,

    EVCOAP_OPT_MAX = EVCOAP_OPT_IF_NONE_MATCH + 1
} evcoap_opt_t;

#define EVCOAP_OPT_SYM_VALID(sy) (sy > EVCOAP_OPT_NONE && sy < EVCOAP_OPT_MAX)

/* Available option types. */
typedef enum 
{
    EVCOAP_OPT_TYPE_INVALID,
    EVCOAP_OPT_TYPE_UINT,   /* 'uint' */
    EVCOAP_OPT_TYPE_STRING, /* 'string' */
    EVCOAP_OPT_TYPE_OPAQUE, /* 'opaque' */
    EVCOAP_OPT_TYPE_EMPTY   /* no type (e.g. if-none-match) */
} evcoap_opt_type_t;

/* A decoded option.  See Sec. 3.2. */
struct evcoap_opt
{
#define EVCOAP_OPT_LEN_MAX  270
    evcoap_opt_t sym;       /* Option internal code (one of EVCOAP_OPT_*.) */
    evcoap_opt_type_t t;    /* Option Type (one of EVCOAP_OPT_TYPE_*.) */
    size_t l;               /* Option Length. */
    ev_uint8_t *v;          /* Raw option Value. */

    TAILQ_ENTRY(evcoap_opt) next;   /* Next in (ordered by num) list. */
};

/* CoAP server socket. */
struct evcoap_bound_socket
{
    /* Bound socket descriptor. */
    evutil_socket_t sd;

    /* Use DTLS. */
    ev_uint8_t secure;

    /* Persistent read event. */
    struct event *ev;

    TAILQ_ENTRY(evcoap_bound_socket) next;
};

/* CoAP client socket. */
struct evcoap_client_socket
{
    /* Socket descriptor. */
    evutil_socket_t sd;

    /* Use DTLS. */
    ev_uint8_t secure;

    /* Read event for messages coming in from request peer. */
    struct event *ev;

    ev_uint16_t mid;        /* MID to be matched to ACK/RST, if CON. */
    ev_uint8_t token[8];    /* Token to be matched. */
    ev_uint8_t token_len;

    /* User installed response callback. */
    evcoap_response_cb_t cb;
    void *cb_args;

    TAILQ_ENTRY(evcoap_client_socket) next;
};

/* 
 * It is hooked to a suitable callback once the URI is known to the parser.
 * TODO log/trace function that prints pdu data synoptically.
 */
struct evcoap_pdu
{
    /* CoAP header fields. */
#define EVCOAP_PDU_HDR_LEN  4
#define COAP_PROTO_VER_1    1
    unsigned int ver:2;
    unsigned int t:2;   /* CON, NON, ACK, RST. */
#define COAP_OPTIONS_MAX    15
    unsigned int oc:4;
    ev_uint8_t code;    /* Request, response or empty. */
    ev_uint16_t mid;
    
#ifndef COAP_REQUEST_SIZE_MAX
#define COAP_REQUEST_SIZE_MAX   1500
#endif  /* !COAP_REQUEST_SIZE_MAX */
    ev_uint8_t *data;
    size_t datalen;
    ev_uint8_t *payload;
    size_t payload_len;
#define EVCOAP_PDU_EMPTY(pdu)   ((pdu)->payload == NULL \
        || ((pdu)->data + (pdu)->datalen) == (pdu)->payload)

    /* Message type and method or response code. */
    evcoap_msg_type_t msg_type;
    evcoap_method_t method;
    evcoap_resp_code_t rcode;

    /* Requesting/requested resource locator. */
    u_uri_t *uri;

    /* Remote and local endpoints. */
    int sd;
    struct sockaddr_storage peer, me;
    ev_socklen_t peer_len, me_len;

    /* Assert if DTLS (may also affect cacheability.)
     * This is a property of the underlying socket and is cached
     * here for commodity -- just like the socket descriptor. */
    ev_uint8_t secure;

    /* Return code from send request operation. */
    evcoap_send_status_t send_status;

    /* Pointer to possibly pending getaddrinfo request. */
    struct evdns_getaddrinfo_request *gai_req;

    /* Options. */
    TAILQ_HEAD(evcoap_opts, evcoap_opt) options;    /* Tokenized opts. */
    size_t noptions;    /* May be less than .oc because of fenceposts. */
};
 
/* TODO take care of length and type fields overhead + fenceposts! */
#define EVCOAP_OPTS_UPPER_LEN   (COAP_OPTIONS_MAX * EVCOAP_OPT_LEN_MAX)

/* ... */
struct evcoap_cb
{
    char *path;
    evcoap_cb_status_t (*fn)(struct evcoap_pdu *, const char *path, void *);
    void *fn_args;
    struct timeval *ack_timeout;
    TAILQ_ENTRY(evcoap_cb) next;
};

/* Expected maximum time to live of a transit PDU. 
 * "[...] retransmission window, calculated as 
 *  RESPONSE_TIMEOUT * RESPONSE_RANDOM_FACTOR * (2 ^ MAX_RETRANSMIT - 1) 
 *  plus the expected maximum round trip time."
 * which should be 2*1.5*(2^4-1)=45+MaxRTT. */
#define EVCOAP_RCVD_TTL_MAX 45

/* Time interval (in seconds) between subsequent purge pass over the rcvd 
 * queue. */
#define EVCOAP_RCVD_CHORES_PERIOD   20

struct evcoap_rcvd_pdu
{
    struct timeval when;        /* When the PDU was received. */
    struct sockaddr_storage ss; /* Sender address. */
    ev_socklen_t ss_len;
    ev_uint16_t mid;            /* PDU Message ID. */
    ev_uint8_t *sent_pdu;       /* Already sent ACK or RST for this PDU. */
    size_t sent_pdu_len;
    TAILQ_ENTRY(evcoap_rcvd_pdu) next;
};

#define EVCOAP_ACK_CHORES_PERIOD    1

struct evcoap_pending_ack
{
    struct timeval when;        /* When the PDU was received. */
    struct timeval timeout;     /* ACK timeout (see evcoap_set_cb_ex().) */
    ev_uint16_t mid;            /* Message-ID that has to be acknowledged. */
    int sd;                     /* Socket descriptor to use for sendto() */
    struct sockaddr_storage ss; /* Receiver address. */
    ev_socklen_t ss_len;
    TAILQ_ENTRY(evcoap_pending_ack) next;
};

struct evcoap_pending_token
{
    ev_uint8_t token[8];    /* Token to be matched. */
    ev_uint8_t token_len;

    /* User installed response callback. */
    void (*cb)(struct evcoap_pdu *, int, void *);
    void *cb_args;

    TAILQ_ENTRY(evcoap_pending_token) next;
};

/* CON messages have one such record active, until it is ACK'd. */
struct evcoap_pending_mid
{
    ev_uint16_t mid;

    /* TODO (design still missing) */
};

/* This is evcoap. */
struct evcoap
{
    ev_uint8_t trace;   /* Enable trace. */

    /* Per (family of) URI callbacks. */
    TAILQ_HEAD(, evcoap_cb) callbacks;

    /* All CoAP listeners for this host. */
    TAILQ_HEAD(, evcoap_bound_socket) servers;

    /* Currently active client sockets. */
    TAILQ_HEAD(, evcoap_client_socket) clients;

    /* Received PDUs queue (for duplicate detection.) */
    TAILQ_HEAD(, evcoap_rcvd_pdu) rcvd_queue;
    struct event *rcvd_queue_handler_interval;

    /* Pending ACKs for incoming CON requests. */
    TAILQ_HEAD(, evcoap_pending_ack) pending_acks;
    struct event *pending_acks_handler_interval;

    /* Outstanding Tokens for outgoing requests. */
    TAILQ_HEAD(, evcoap_pending_token) pending_tokens;

    /* Outstanding MIDs (used for automatic handling of ACKs and retransmission 
     * of CON PDUs.) */
    TAILQ_HEAD(, evcoap_pending_mid) pending_mids;

    /* Fall back handler invoked when the requested URI didn't match any of the
     * callbacks. */
    void (*fb)(struct evcoap_pdu *, const char *, void *);
    void *fb_args;

    /* Reference to the libevent base where all evcoap events are installed. */
    struct evdns_base *dns;
    struct event_base *base;
};

struct evcoap_sendreq_args
{
    struct evcoap *coap;
    struct evcoap_pdu *pdu;
    evcoap_response_cb_t cb;
    void *cb_args;
    struct timeval *timeout;
};

/* Server sockets. */
struct evcoap_bound_socket *evcoap_bound_socket_new(struct evcoap *coap,
        evutil_socket_t sd, ev_uint8_t secure);
void evcoap_bound_socket_free(struct evcoap_bound_socket *bs);
int evcoap_bound_socket_get_secure(struct evcoap *coap, int sd, 
        ev_uint8_t *psecure);
evutil_socket_t evcoap_do_bind_socket(struct sockaddr_storage *ss,
        ev_socklen_t ss_len);

/* Client sockets. */
struct evcoap_client_socket *evcoap_client_socket_new(struct evcoap *coap,
        evutil_socket_t sd, ev_uint16_t mid, ev_uint8_t *tok, size_t tok_len,
        evcoap_response_cb_t cb, void *cb_args);
int evcoap_client_socket_add(struct evcoap *coap, evcoap_response_cb_t cb, 
        void *cb_args, struct evcoap_pdu *pdu);
void evcoap_client_socket_free(struct evcoap_client_socket *cs);

/* Input processing entry point. */
void evcoap_input (int sd, short what, void *u);

/* Misc stuff. */
void evcoap_cb_free(struct evcoap_cb *cb);
void evcoap_build_header(ev_uint8_t ver, ev_uint8_t t, ev_uint8_t oc, 
        ev_uint8_t code, ev_uint16_t mid, ev_uint8_t hdr[4]);
int evcoap_send(struct evcoap *coap, int sd, 
        const struct sockaddr_storage *ss, ev_socklen_t ss_len,
        const ev_uint8_t *hdr, const ev_uint8_t *opts, size_t opts_len,
        const ev_uint8_t *payload, size_t payload_len);
void evcoap_sendreq_dns_cb(int result, struct evutil_addrinfo *res, void *arg);
int evcoap_resolv_async(struct evcoap *coap, struct evcoap_pdu *pdu);
struct evcoap_sendreq_args *evcoap_sendreq_args_new(struct evcoap *coap, 
        struct evcoap_pdu *pdu, evcoap_response_cb_t cb, void *cb_args, 
        struct timeval *timeout);
void evcoap_sendreq_args_free(struct evcoap_sendreq_args *sendreq_args);

/* Automatic ACK handling. */
int evcoap_pending_ack_sched(struct evcoap *coap, ev_uint16_t mid,
        const struct timeval *tout, evutil_socket_t sd, 
        const struct sockaddr_storage *ss, ev_socklen_t ss_len);
void evcoap_pending_acks_chores (evutil_socket_t u0, short u1, void *c);
void evcoap_pending_ack_free(struct evcoap_pending_ack *pack);

struct evcoap_bound_socket *evcoap_socket_is_server(struct evcoap *coap,
        evutil_socket_t sd);
struct evcoap_client_socket *evcoap_socket_is_client(struct evcoap *coap,
        evutil_socket_t sd);

/* PDU handling. */
int evcoap_pdu_client_input(struct evcoap *coap, struct evcoap_pdu *pdu,
        struct evcoap_client_socket *cs);
int evcoap_pdu_server_input(struct evcoap *coap, struct evcoap_pdu *pdu,
        struct evcoap_bound_socket *bs);
struct evcoap_pdu *evcoap_pdu_new_received(struct evcoap *coap, int sd,
        const ev_uint8_t *d, size_t dlen, const struct sockaddr_storage *peer, 
        const ev_socklen_t peer_len);
int evcoap_pdu_uri_compose(struct evcoap_pdu *pdu);
int evcoap_pdu_uri_compose_proxy(struct evcoap_pdu *pdu);
int evcoap_pdu_uri_compose_tokens(struct evcoap_pdu *pdu);
void evcoap_pdu_free(struct evcoap_pdu *pdu);
int evcoap_pdu_sanitize_send(struct evcoap_pdu *pdu);
int evcoap_pdu_sanitize_send_req(struct evcoap *coap, struct evcoap_pdu *pdu);

evcoap_msg_type_t evcoap_msg_type_decode(ev_uint8_t code);
int evcoap_method_decode(ev_uint8_t code, evcoap_method_t *pm);
int evcoap_resp_code_decode(ev_uint8_t code, evcoap_resp_code_t *pc);

/* Received PDUs queue. */
int evcoap_dup_handler(struct evcoap *coap, int sd, ev_uint16_t mid, 
        const struct sockaddr_storage *ss, ev_socklen_t ss_len);
struct evcoap_rcvd_pdu *evcoap_rcvd_pdu_new(ev_uint16_t mid,
        struct timeval *when, const struct sockaddr_storage *ss, 
        ev_socklen_t ss_len);
void evcoap_rcvd_pdu_free(struct evcoap_rcvd_pdu *rcvd);
void evcoap_rcvd_queue_chores (evutil_socket_t u0, short u1, void *arg);

/* Options processing. */
int evcoap_opts_encode(struct evcoap_pdu *pdu, ev_uint8_t *b, size_t *plen);
const char *evcoap_pdu_get_string_opt(struct evcoap_pdu *pdu, evcoap_opt_t sym);
int evcoap_pdu_get_uint_opt(struct evcoap_pdu *pdu, evcoap_opt_t sym, 
        ev_uint64_t *pui);
const char *evcoap_opt_get_string_pretty(struct evcoap_opt *opt);
int evcoap_opt_get_uint_pretty(struct evcoap_opt *opt, ev_uint64_t *pui);
int evcoap_opt_add(struct evcoap_pdu *pdu, evcoap_opt_t sym,
        const ev_uint8_t *v, size_t l);
int evcoap_opt_encode(struct evcoap_pdu *pdu);
int evcoap_opt_parse(struct evcoap_pdu *pdu);
int evcoap_opt_add_uint(struct evcoap_pdu *pdu, evcoap_opt_t sym, 
        ev_uint64_t v);
int evcoap_opt_add_raw(struct evcoap_pdu *pdu, evcoap_opt_t sym,
        const ev_uint8_t *v, size_t l);
int evcoap_opt_add_string(struct evcoap_pdu *pdu, evcoap_opt_t sym,
        const char *s);
int evcoap_opt_add_opaque(struct evcoap_pdu *pdu, evcoap_opt_t sym,
        const ev_uint8_t *v,  size_t l);
int evcoap_opt_add_empty(struct evcoap_pdu *pdu, evcoap_opt_t sym);
struct evcoap_opt *evcoap_opt_get(struct evcoap_pdu *pdu, evcoap_opt_t sym);
struct evcoap_opt *evcoap_opt_get_nth(struct evcoap_pdu *pdu, evcoap_opt_t sym, 
        size_t n);
size_t evcoap_opt_sym2num(evcoap_opt_t sym);
evcoap_opt_t evcoap_opt_num2sym(size_t num);
const char *evcoap_opt_sym2str(evcoap_opt_t sym);
evcoap_opt_type_t evcoap_opt_sym2type(evcoap_opt_t sym);
int evcoap_opt_set(struct evcoap_opt *opt, evcoap_opt_t sym,
        const ev_uint8_t *val, size_t len);
int evcoap_opt_decode_uint(const ev_uint8_t *ui, size_t len, 
        ev_uint64_t *pui);
int evcoap_opt_encode_uint(ev_uint64_t ui, ev_uint8_t *e, size_t *len);
void evcoap_opt_free(struct evcoap_opt *opt);
struct evcoap_opt *evcoap_opt_new_empty(void);
int evcoap_opt_push(struct evcoap_pdu *pdu, struct evcoap_opt *opt);

#endif  /* !_EVCOAP_PRIV_H_ */
