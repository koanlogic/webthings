#ifndef _EC_H_
#define _EC_H_

#include <event2/dns.h>
#include <event2/util.h>
#include <event2/event.h>

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

struct ec_s;
struct ec_pdu_s;

typedef struct ec_s ec_t;
typedef struct ec_pdu_s ec_pdu_t;

#define EC_DEFAULT_PORT 5683

typedef enum
{
    EC_CON = 0,
    EC_NON = 1,
    EC_ACK = 2,
    EC_RST = 3
} ec_pdu_type_t;

typedef enum
{
    EC_GET    = 1,
    EC_PUT    = 2,
    EC_POST   = 3,
    EC_DELETE = 4
} ec_method_t;

/* Available Media types. */
typedef enum
{
    EC_MT_TEXT_PLAIN               = 0,
    EC_MT_APPLICATION_LINK_FORMAT  = 40,
    EC_MT_APPLICATION_XML          = 41,
    EC_MT_APPLICATION_OCTET_STREAM = 42,
    EC_MT_APPLICATION_EXI          = 47,
    EC_MT_APPLICATION_JSON         = 50
} ec_mt_t;

/* Available Response Codes. */
typedef enum
{
    EC_RC_UNSET                    = 0,  /* Invalid. */

    /*
     * Class 2.xx (ok)
     */
    EC_CREATED                  = 65,  /* 2.01 */
    EC_DELETED                  = 66,  /* 2.02 */
    EC_VALID                    = 67,  /* 2.03 */
    EC_CHANGED                  = 68,  /* 2.04 */
    EC_CONTENT                  = 69,  /* 2.05 */
    EC_200_UNKNOWN              = 95,  /* Highest 2.xx */

    /*
     * Class 4.xx (client error)
     */
    EC_BAD_REQUEST              = 128,  /* 4.00 */
    EC_UNAUTHORIZED             = 129,  /* 4.01 */
    EC_BAD_OPTION               = 130,  /* 4.02 */
    EC_FORBIDDEN                = 131,  /* 4.03 */
    EC_NOT_FOUND                = 132,  /* 4.04 */
    EC_METHOD_NOT_ALLOWED       = 133,  /* 4.05 */
    EC_NOT_ACCEPTABLE           = 134,  /* 4.06 */
    EC_PRECONDITION_FAILED      = 140,  /* 4.12 */
    EC_REQUEST_ENTITY_TOO_LARGE = 141,  /* 4.13 */
    EC_UNSUPPORTED_MEDIA_TYPE   = 143,  /* 4.15 */
    EC_400_UNKNOWN              = 159,  /* Highest 4.xx */

    /*
     * Class 5.xx (server error)
     */
    EC_INTERNAL_SERVER_ERROR    = 160,  /* 5.00 */
    EC_NOT_IMPLEMENTED          = 161,  /* 5.01 */
    EC_BAD_GATEWAY              = 162,  /* 5.02 */
    EC_SERVICE_UNAVAILABLE      = 163,  /* 5.03 */
    EC_GATEWAY_TIMEOUT          = 164,  /* 5.04 */
    EC_PROXYING_NOT_SUPPORTED   = 165,  /* 5.05 */
    EC_500_UNKNOWN              = 191   /* Highest 5.xx */
} ec_rc_t;
#define EC_IS_RESP_CODE(rc) \
    ((rc) >= EC_CREATED && (rc) <= EC_500_UNKNOWN)

/* Final states for the client FSM. */
typedef enum
{
    EC_SEND_OK = 0,
    EC_DNS_FAILED,
    EC_SEND_FAILED,
    EC_PROTO_TIMEOUT,
    EC_APP_TIMEOUT
} ec_send_status_t;

/* Setup / Teardown / Control. */
ec_t *ec_init(struct event_base *base, struct evdns_base *dns);
void ec_term(ec_t *coap);

/* Client API */
typedef void (*ec_client_cb_t)(ec_t *coap, ec_pdu_t *res,
        ec_send_status_t status, void *args);

ec_pdu_t *ec_new_request(ec_method_t m, const char *uri);

ec_pdu_t *ec_new_proxy_request(ec_method_t m, const char *uri,
        const char *proxy_host, ev_uint16_t proxy_port);

int ec_send_request(ec_t *coap, ec_pdu_t *req, ec_pdu_type_t pt, 
        ec_client_cb_t cb, void *cb_args);

/* Server API */
typedef int (*ec_server_cb_t)(ec_t *coap, ec_pdu_t *req, ec_pdu_t *res, 
        void *args, ev_uint8_t resched, struct timeval *resched_after);

int ec_bind_socket(ec_t *coap, const char *addr, ev_uint16_t port);

int ec_set_cb(ec_t *coap, const char *patt, ec_server_cb_t cb,
        void *cb_args, ev_uint8_t observable);

int ec_set_gencb(ec_t *coap, ec_server_cb_t cb, void *cb_args,
        ev_uint8_t observable);

/* PDU manipulation API */
int ec_set_payload(ec_pdu_t *req, ev_uint8_t *payload, size_t sz);

int ec_set_response_code(ec_pdu_t *res, ec_rc_t rc);

int ec_add_content_type_option(struct ec_pdu_s *req, ev_uint16_t ct);
int ec_add_max_age_option(struct ec_pdu_s *req, ev_uint32_t ma);
int ec_add_proxy_uri_option(struct ec_pdu_s *req, const char *pu);
int ec_pdu_add_etag(struct ec_pdu_s *req, const ev_uint8_t *et, size_t et_len);
int ec_add_uri_host_option(struct ec_pdu_s *req, const char  *uh);
int ec_add_location_path_option(struct ec_pdu_s *req, const char *lp);
int ec_add_uri_port_option(struct ec_pdu_s *req, ev_uint16_t up);
int ec_add_location_query_option(struct ec_pdu_s *req, const char *lq);
int ec_add_uri_path_option(struct ec_pdu_s *req, const char *up);
int ec_add_token_option(struct ec_pdu_s *req, const ev_uint8_t *t,
        size_t t_len);
int ec_add_accept_option(struct ec_pdu_s *req, ev_uint16_t a);
int ec_add_if_match_option(struct ec_pdu_s *req, const ev_uint8_t *im,
        size_t im_len);
int ec_add_uri_query_option(struct ec_pdu_s *pdu, const char *uq);
int ec_add_if_none_match_option(struct ec_pdu_s *req);
int ec_add_observe_option(struct ec_pdu_s *req, ev_uint16_t o);
int ec_add_max_ofe_option(struct ec_pdu_s *req, ev_uint32_t mo);

/* Observe API */
int ec_update_representation(const char *uri, const ev_uint8_t *rep,
        size_t rep_len, ec_mt_t media_type);

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif  /* !_EC_H_ */
