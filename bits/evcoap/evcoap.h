#ifndef _EVCOAP_H_
#define _EVCOAP_H_

//#include <event2/event.h>
#include <event2/dns.h>
#include <event2/util.h>
#include <event2/event.h>

#define COAP_DEFAULT_SERVER_PORT        5683
#define COAP_DEFAULT_SERVER_PORT_STR    "5683"

struct evcoap;
struct evcoap_pdu;

/* Available PDU types. */
typedef enum 
{
    EVCOAP_PDU_TYPE_CON = 0,
    EVCOAP_PDU_TYPE_NON = 1,
    EVCOAP_PDU_TYPE_ACK = 2,
    EVCOAP_PDU_TYPE_RST = 3
} evcoap_pdu_type_t;
#define EVCOAP_PDU_TYPE_VALID(t)    ((t) <= EVCOAP_PDU_TYPE_RST)

/* Sec. 5.2.: "Response Codes in the Client Error and Server Error class that
 * are unrecognized by an end-point MUST be treated as being equivalent to the 
 * generic Response Code of that class." */
/* XXX I'm in doubt wheather to expose the raw codes. */
typedef enum
{
    EVCOAP_RESP_CODE_UNSET                    = 0,  /* Invalid. */

    /*
     * Class 2.xx (ok)
     */
    EVCOAP_RESP_CODE_CREATED                  = 65,  /* 2.01 */
    EVCOAP_RESP_CODE_DELETED                  = 66,  /* 2.02 */
    EVCOAP_RESP_CODE_VALID                    = 67,  /* 2.03 */
    EVCOAP_RESP_CODE_CHANGED                  = 68,  /* 2.04 */
    EVCOAP_RESP_CODE_CONTENT                  = 69,  /* 2.05 */
    EVCOAP_RESP_CODE_200_UNKNOWN              = 95,  /* Highest 2.xx */

    /*
     * Class 4.xx (client error)
     */
    EVCOAP_RESP_CODE_BAD_REQUEST              = 128,  /* 4.00 */
    EVCOAP_RESP_CODE_UNAUTHORIZED             = 129,  /* 4.01 */
    EVCOAP_RESP_CODE_BAD_OPTION               = 130,  /* 4.02 */
    EVCOAP_RESP_CODE_FORBIDDEN                = 131,  /* 4.03 */
    EVCOAP_RESP_CODE_NOT_FOUND                = 132,  /* 4.04 */
    EVCOAP_RESP_CODE_METHOD_NOT_ALLOWED       = 133,  /* 4.05 */
    EVCOAP_RESP_CODE_NOT_ACCEPTABLE           = 134,  /* 4.06 */
    EVCOAP_RESP_CODE_PRECONDITION_FAILED      = 140,  /* 4.12 */
    EVCOAP_RESP_CODE_REQUEST_ENTITY_TOO_LARGE = 141,  /* 4.13 */
    EVCOAP_RESP_CODE_UNSUPPORTED_MEDIA_TYPE   = 143,  /* 4.15 */
    EVCOAP_RESP_CODE_400_UNKNOWN              = 159,  /* Highest 4.xx */

    /*
     * Class 5.xx (server error)
     */
    EVCOAP_RESP_CODE_INTERNAL_SERVER_ERROR    = 160,  /* 5.00 */
    EVCOAP_RESP_CODE_NOT_IMPLEMENTED          = 161,  /* 5.01 */
    EVCOAP_RESP_CODE_BAD_GATEWAY              = 162,  /* 5.02 */
    EVCOAP_RESP_CODE_SERVICE_UNAVAILABLE      = 163,  /* 5.03 */
    EVCOAP_RESP_CODE_GATEWAY_TIMEOUT          = 164,  /* 5.04 */
    EVCOAP_RESP_CODE_PROXYING_NOT_SUPPORTED   = 165,  /* 5.05 */
    EVCOAP_RESP_CODE_500_UNKNOWN              = 191   /* Highest 5.xx */

} evcoap_resp_code_t;

/* CoAP methods. */
typedef enum
{
    EVCOAP_METHOD_UNSET   = 0,  /* Invalid. */
    EVCOAP_METHOD_GET     = 1,
    EVCOAP_METHOD_POST    = 2,
    EVCOAP_METHOD_PUT     = 3,
    EVCOAP_METHOD_DELETE  = 4
} evcoap_method_t;
#define EVCOAP_METHOD_VALID(m)  \
    ((m) > EVCOAP_METHOD_UNSET && (m) <= EVCOAP_METHOD_DELETE)

/* Available Content-Type's. */
typedef enum
{
    EVCOAP_CT_TEXT_PLAIN = 0,
    EVCOAP_CT_APPLICATION_LINK_FORMAT = 40,
    EVCOAP_CT_APPLICATION_XML = 41,
    EVCOAP_CT_APPLICATION_OCTET_STREAM = 42,
    EVCOAP_CT_APPLICATION_EXI = 47,
    EVCOAP_CT_APPLICATION_JSON = 50
} evcoap_ct_t;

/* Callback return codes. */
typedef enum 
{
    EVCOAP_CB_STATUS_RESP_SENT = 0,     /* Response sent. */
    EVCOAP_CB_STATUS_ACK_SENT  = 1,     /* ACK sent */
    EVCOAP_CB_STATUS_ACK_AUTO  = 2      /* Let evcoap handle the ACK logics. */
} evcoap_cb_status_t;


typedef enum 
{
    EVCOAP_SEND_STATUS_OK = 0,
    EVCOAP_SEND_STATUS_ERR,
    EVCOAP_SEND_STATUS_DNS_FAIL
} evcoap_send_status_t;

/* Event handling. */
struct evcoap *evcoap_new(struct event_base *base, struct evdns_base *dns);
void evcoap_free(struct evcoap *coap);
int evcoap_loopexit(struct evcoap *coap, const struct timeval *tv);
int evcoap_loopbreak(struct evcoap *coap);


/* Server socket creation. */
int evcoap_bind_socket(struct evcoap *coap, const char *addr, ev_uint16_t port,
        ev_uint8_t secure);

/* Server callbacks. */
int evcoap_set_gencb(struct evcoap *coap, 
        void (*cb)(struct evcoap_pdu *, const char *, void *), void *cb_arg);
int evcoap_del_gencb(struct evcoap *coap);

/* This "extended" version of the evcoap_set_cb() must be used whenever the user
 * is not replying immediately (i.e. within the invoked callback scope.)
 * E.g. the callback initializes a batch task to be performed in order to
 * produce the response, and sets another callback that notifies the completion
 * of the batch task (-> response ready.)
 * In case the callback is able to produce the response immediately, it shall
 * communicate this to the evcoap library by returning EVCOAP_CB_STATUS_DONE,
 * or, in case it has produced just the ACK message (anyway, that'd be strange)
 * with EVCOAP_CB_STATUS_ACK_SENT.  If the request has been batch-scheduled
 * and the user wants the library to handle the ACK'ing transparently, it shall
 * return EVCOAP_CB_STATUS_ACK_AUTO. */
int evcoap_set_cb_ex(struct evcoap *coap, const char *pattern,
        evcoap_cb_status_t (*cb)(struct evcoap_pdu *, const char *, void *),
        void *cb_arg, const struct timeval *ack_timeout);
int evcoap_set_cb(struct evcoap *coap, const char *pattern,
        evcoap_cb_status_t (*cb)(struct evcoap_pdu *, const char *, void *), 
        void *cb_arg);
int evcoap_del_cb(struct evcoap *coap, const char *pattern);

/* PDU creation/handling. */
struct evcoap_pdu *evcoap_pdu_new_empty(void);

struct evcoap_pdu *evcoap_request_new(evcoap_pdu_type_t pdu_type, 
        evcoap_method_t method, const char *uri);

struct evcoap_pdu *evcoap_proxy_request_new(evcoap_pdu_type_t pdu_type,
        evcoap_method_t method, const char *uri, const char *proxy_host, 
        ev_uint16_t port);

struct evcoap_pdu *evcoap_request_new_ex(evcoap_pdu_type_t pdu_type,
        evcoap_method_t method, const char *uri, ev_uint8_t use_proxy,
        const char *proxy_host, ev_uint16_t proxy_port);

evcoap_resp_code_t evcoap_pdu_get_resp_status(struct evcoap_pdu *pdu);

/* Payload */
int evcoap_pdu_set_payload(struct evcoap_pdu *pdu, const ev_uint8_t *p,
        size_t plen);
const ev_uint8_t *evcoap_pdu_get_payload(struct evcoap_pdu *pdu, size_t *plen);

/* Header */
int evcoap_pdu_resp_set_header(struct evcoap_pdu *pdu,
        evcoap_pdu_type_t pdu_type, evcoap_resp_code_t resp_code, 
        ev_uint16_t message_id);

int evcoap_pdu_req_set_header(struct evcoap_pdu *pdu,
        evcoap_pdu_type_t pdu_type, evcoap_method_t method);

/* Options */
int evcoap_pdu_add_content_type(struct evcoap_pdu *pdu, ev_uint16_t ct);
int evcoap_pdu_add_max_age(struct evcoap_pdu *pdu, ev_uint32_t ma);
int evcoap_pdu_add_proxy_uri(struct evcoap_pdu *pdu, const char *pu);
int evcoap_pdu_add_etag(struct evcoap_pdu *pdu, const ev_uint8_t *et,
        size_t et_len);
int evcoap_pdu_add_uri_host(struct evcoap_pdu *pdu, const char  *uh);
int evcoap_pdu_add_location_path(struct evcoap_pdu *pdu, const char *lp);
int evcoap_pdu_add_uri_port(struct evcoap_pdu *pdu, ev_uint16_t up);
int evcoap_pdu_add_location_query(struct evcoap_pdu *pdu, const char *lq);
int evcoap_pdu_add_uri_path(struct evcoap_pdu *pdu, const char *up);
int evcoap_pdu_add_token(struct evcoap_pdu *pdu, const ev_uint8_t *t,
        size_t t_len);
int evcoap_pdu_add_accept(struct evcoap_pdu *pdu, ev_uint16_t a);
int evcoap_pdu_add_if_match(struct evcoap_pdu *pdu, const ev_uint8_t *im,
        size_t im_len);
int evcoap_pdu_add_uri_query(struct evcoap_pdu *pdu, const char *uq);
int evcoap_pdu_add_if_none_match(struct evcoap_pdu *pdu);
int evcoap_pdu_add_observe(struct evcoap_pdu *pdu, ev_uint16_t o);
int evcoap_pdu_add_max_ofe(struct evcoap_pdu *pdu, ev_uint32_t mo);

const char *evcoap_pdu_get_uri_host(struct evcoap_pdu *pdu);
int evcoap_pdu_get_uri_port(struct evcoap_pdu *pdu, ev_uint16_t *port);
const char *evcoap_pdu_get_proxy_uri(struct evcoap_pdu *pdu);

/* Sending requests. */
typedef void (*evcoap_response_cb_t)(struct evcoap *, struct evcoap_pdu *, 
        evcoap_send_status_t, void *);

int evcoap_send_request(struct evcoap *coap, struct evcoap_pdu *pdu,
        evcoap_response_cb_t cb, void *cb_args, struct timeval *timeout);

#endif  /* !_EVCOAP_H_ */
