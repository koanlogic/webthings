#ifndef _EVCOAP_H_
#define _EVCOAP_H_

#include <event2/dns.h>
#include <event2/util.h>
#include <event2/event.h>

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

struct evcoap_s;
struct evcoap_pdu_s;

typedef struct evcoap_s evcoap_t;
typedef struct evcoap_pdu_s evcoap_pdu_t;

#define EVCOAP_DEFAULT_PORT 5683

typedef enum
{
    EVCOAP_CON = 0,
    EVCOAP_NON = 1,
    EVCOAP_ACK = 2,
    EVCOAP_RST = 3
} evcoap_pdu_type_t;

typedef enum
{
    EVCOAP_GET    = 1,
    EVCOAP_PUT    = 2,
    EVCOAP_POST   = 3,
    EVCOAP_DELETE = 4
} evcoap_method_t;

/* Available Media types. */
typedef enum
{
    EVCOAP_MT_TEXT_PLAIN               = 0,
    EVCOAP_MT_APPLICATION_LINK_FORMAT  = 40,
    EVCOAP_MT_APPLICATION_XML          = 41,
    EVCOAP_MT_APPLICATION_OCTET_STREAM = 42,
    EVCOAP_MT_APPLICATION_EXI          = 47,
    EVCOAP_MT_APPLICATION_JSON         = 50
} evcoap_mt_t;

/* Available Response Codes. */
typedef enum
{
    EVCOAP_RC_UNSET                    = 0,  /* Invalid. */

    /*
     * Class 2.xx (ok)
     */
    EVCOAP_CREATED                  = 65,  /* 2.01 */
    EVCOAP_DELETED                  = 66,  /* 2.02 */
    EVCOAP_VALID                    = 67,  /* 2.03 */
    EVCOAP_CHANGED                  = 68,  /* 2.04 */
    EVCOAP_CONTENT                  = 69,  /* 2.05 */
    EVCOAP_200_UNKNOWN              = 95,  /* Highest 2.xx */

    /*
     * Class 4.xx (client error)
     */
    EVCOAP_BAD_REQUEST              = 128,  /* 4.00 */
    EVCOAP_UNAUTHORIZED             = 129,  /* 4.01 */
    EVCOAP_BAD_OPTION               = 130,  /* 4.02 */
    EVCOAP_FORBIDDEN                = 131,  /* 4.03 */
    EVCOAP_NOT_FOUND                = 132,  /* 4.04 */
    EVCOAP_METHOD_NOT_ALLOWED       = 133,  /* 4.05 */
    EVCOAP_NOT_ACCEPTABLE           = 134,  /* 4.06 */
    EVCOAP_PRECONDITION_FAILED      = 140,  /* 4.12 */
    EVCOAP_REQUEST_ENTITY_TOO_LARGE = 141,  /* 4.13 */
    EVCOAP_UNSUPPORTED_MEDIA_TYPE   = 143,  /* 4.15 */
    EVCOAP_400_UNKNOWN              = 159,  /* Highest 4.xx */

    /*
     * Class 5.xx (server error)
     */
    EVCOAP_INTERNAL_SERVER_ERROR    = 160,  /* 5.00 */
    EVCOAP_NOT_IMPLEMENTED          = 161,  /* 5.01 */
    EVCOAP_BAD_GATEWAY              = 162,  /* 5.02 */
    EVCOAP_SERVICE_UNAVAILABLE      = 163,  /* 5.03 */
    EVCOAP_GATEWAY_TIMEOUT          = 164,  /* 5.04 */
    EVCOAP_PROXYING_NOT_SUPPORTED   = 165,  /* 5.05 */
    EVCOAP_500_UNKNOWN              = 191   /* Highest 5.xx */
} evcoap_rc_t;

/* Final states for the client FSM. */
typedef enum
{
    EVCOAP_SEND_OK = 0,
    EVCOAP_DNS_FAILED,
    EVCOAP_SEND_FAILED,
    EVCOAP_PROTO_TIMEOUT,
    EVCOAP_APP_TIMEOUT
} evcoap_send_status_t;

/* Setup / Teardown / Control. */
evcoap_t *evcoap_init(struct event_base *base, struct evdns_base *dns);
void evcoap_term(evcoap_t *coap);

/* Client API */
typedef void (*evcoap_client_cb_t)(evcoap_t *coap, evcoap_pdu_t *res,
        evcoap_send_status_t status, void *args);

evcoap_pdu_t *evcoap_new_request(evcoap_method_t m, const char *uri);

evcoap_pdu_t *evcoap_new_proxy_request(evcoap_method_t m, const char *uri,
        const char *proxy_host, ev_uint16_t proxy_port);

int evcoap_send_request(evcoap_t *coap, evcoap_pdu_t *req, 
        evcoap_pdu_type_t pt, evcoap_client_cb_t cb, void *cb_args);

/* Server API */
typedef int (*evcoap_server_cb_t)(evcoap_t *coap, evcoap_pdu_t *req,
        evcoap_pdu_t *res, void *args, ev_uint8_t resched, 
        struct timeval *resched_after);

int evcoap_bind_socket(evcoap_t *coap, const char *addr, ev_uint16_t port);

int evcoap_set_cb(evcoap_t *coap, const char *patt, evcoap_server_cb_t cb,
        void *cb_args, ev_uint8_t observable);

int evcoap_set_gencb(evcoap_t *coap, evcoap_server_cb_t cb, void *cb_args,
        ev_uint8_t observable);

/* PDU manipulation API */
int evcoap_set_payload(evcoap_pdu_t *req, ev_uint8_t *payload, size_t sz);

int evcoap_set_response_code(evcoap_pdu_t *res, evcoap_rc_t rc);

int evcoap_add_ifmatch_option(evcoap_pdu_t *req, ev_uint8_t *tag, size_t sz);
int evcoap_add_accept_option(evcoap_pdu_t *req, evcoap_mt_t mt);

/* Observe API */
int evcoap_update_representation(const char *uri, const ev_uint8_t *rep,
        size_t rep_len, evcoap_mt_t media_type);

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif  /* !_EVCOAP_H_ */
