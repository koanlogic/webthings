#ifndef _EC_ENUMS_H_
#define _EC_ENUMS_H_

#include <event2/dns.h>
#include <event2/util.h>
#include <event2/event.h>

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

#define EC_COAP_VERSION_1       1

#define EC_COAP_DEFAULT_PORT    5683
#define EC_COAP_DEFAULT_SPORT   "5683"

#define EC_COAP_OPT_LEN_MAX 270
#define EC_COAP_MAX_OPTIONS 15
#define EC_COAP_HDR_SIZE    4

/* Max-age default. */
#define EC_COAP_DEFAULT_MAX_AGE 60

/* Block Options size range. */
#define EC_COAP_BLOCK_MIN   (1 << 4)
#define EC_COAP_BLOCK_MAX   (1 << 10)

/* CON retransmission parameters. */
#define EC_COAP_RESP_TIMEOUT        2
#define EC_COAP_RESP_RANDOM_FACTOR  1.5
#define EC_COAP_MAX_RETRANSMIT      4

#ifndef EC_COAP_MAX_REQ_SIZE
  #define EC_COAP_MAX_REQ_SIZE 1500
#endif  /* !EC_COAP_MAX_REQ_SIZE */

#define EC_URI_MAX  512

/* CoAP Message Types. */
typedef enum
{
    EC_COAP_CON = 0,
    EC_COAP_NON = 1,
    EC_COAP_ACK = 2,
    EC_COAP_RST = 3
} ec_msg_model_t;

const char *ec_model_str(ec_msg_model_t model);

/* CoAP Method Codes. */
typedef enum
{
    EC_METHOD_UNSET  = 0,
    EC_COAP_GET      = 1,
    EC_COAP_POST     = 2,
    EC_COAP_PUT      = 3,
    EC_COAP_DELETE   = 4,
    EC_METHOD_MAX    = EC_COAP_DELETE + 1
} ec_method_t;
#define EC_IS_METHOD(m) ((m) > EC_METHOD_UNSET && (m) < EC_METHOD_MAX)

const char *ec_method_str(ec_method_t method);

/* Evcoap method masks. */
typedef enum
{
    EC_METHOD_MASK_UNSET    = 0,
    EC_GET_MASK             = (1 << (EC_COAP_GET - 1)),
    EC_POST_MASK            = (1 << (EC_COAP_POST - 1)),
    EC_PUT_MASK             = (1 << (EC_COAP_PUT - 1)),
    EC_DELETE_MASK          = (1 << (EC_COAP_DELETE - 1)),
    EC_METHOD_MASK_ALL      = (EC_GET_MASK | EC_PUT_MASK | EC_POST_MASK |
                               EC_DELETE_MASK)
} ec_method_mask_t;
#define EC_IS_METHOD_MASK(m) ((m) > EC_METHOD_MASK_UNSET && \
        (m) <= EC_METHOD_MASK_ALL)

ec_method_mask_t ec_method_to_mask(ec_method_t method);

/* Available Media types.
 * "The identifiers between 201 and 255 inclusive are reserved for Private Use."
 * Evcoap reserves 255 for "any media type", which is used as a wild-card in 
 * resource lookup (see extra/include/evcoap_filesys.h.) */
typedef enum
{
    EC_MT_TEXT_PLAIN               = 0,
    EC_MT_APPLICATION_LINK_FORMAT  = 40,
    EC_MT_APPLICATION_XML          = 41,
    EC_MT_APPLICATION_OCTET_STREAM = 42,
    EC_MT_APPLICATION_EXI          = 47,
    EC_MT_APPLICATION_JSON         = 50,
    EC_MT_ANY                      = 255    /* RESERVED by evcoap. */
} ec_mt_t;

int ec_mt_from_string(const char *s, ec_mt_t *pmt);

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
#define EC_IS_OK(rc) \
    ((rc) >= EC_CREATED && (rc) <= EC_200_UNKNOWN)
#define EC_IS_RESP_CODE(rc) \
    ((rc) >= EC_CREATED && (rc) <= EC_500_UNKNOWN)

const char *ec_rc_str(ec_rc_t rc);
const char *ec_code_str(unsigned int rc);    /* full CoAP Code Registry */

/* Client transaction states. */
typedef enum
{
    EC_CLI_STATE_NONE = 0,
    EC_CLI_STATE_INTERNAL_ERR,      /* F */
    EC_CLI_STATE_DNS_FAILED,        /* F */
    EC_CLI_STATE_DNS_OK,
    EC_CLI_STATE_SEND_FAILED,       /* F */
    EC_CLI_STATE_REQ_SENT,
    EC_CLI_STATE_REQ_ACKD,
    EC_CLI_STATE_APP_TIMEOUT,       /* F */
    EC_CLI_STATE_COAP_RETRY,
    EC_CLI_STATE_COAP_TIMEOUT,      /* F */
    EC_CLI_STATE_REQ_DONE,          /* F */
    EC_CLI_STATE_REQ_RST,           /* F */
    EC_CLI_STATE_WAIT_NFY,
    EC_CLI_STATE_OBS_TIMEOUT,       /* F */

    EC_CLI_STATE_MAX = EC_CLI_STATE_OBS_TIMEOUT
} ec_cli_state_t;

const char *ec_cli_state_str(ec_cli_state_t s);

/* Server transaction states. */
typedef enum 
{
    EC_SRV_STATE_NONE = 0,
    EC_SRV_STATE_INTERNAL_ERR,      /* F */
    EC_SRV_STATE_DUP_REQ,           /* F */
    EC_SRV_STATE_BAD_REQ,           /* F */
    EC_SRV_STATE_REQ_OK,
    EC_SRV_STATE_ACK_SENT,
    EC_SRV_STATE_WAIT_ACK,
    EC_SRV_STATE_RESP_ACK_TIMEOUT,  /* F */
    EC_SRV_STATE_RESP_DONE,         /* F */
    EC_SRV_STATE_COAP_RETRY,
    EC_SRV_STATE_CLIENT_RST,        /* F */

    EC_SRV_STATE_MAX = EC_SRV_STATE_CLIENT_RST
} ec_srv_state_t;

const char *ec_srv_state_str(ec_srv_state_t s);

/* Callback to evcoap contract. */
typedef enum
{
    EC_CBRC_READY = 0,
    EC_CBRC_WAIT,
    EC_CBRC_POLL,
    EC_CBRC_ERROR
} ec_cbrc_t;

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif  /* !_EC_ENUMS_H_ */
