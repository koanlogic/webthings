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

#define EC_COAP_CON    0
#define EC_COAP_NON    1
#define EC_COAP_ACK    2
#define EC_COAP_RST    3

#define EC_COAP_OPT_LEN_MAX 270
#define EC_COAP_MAX_OPTIONS 15
#define EC_COAP_HDR_SIZE    4

typedef enum
{
    EC_CON = 0,
    EC_NON = 1,
} ec_msg_model_t;

typedef enum
{
    EC_METHOD_UNSET  = 0,
    EC_GET           = 1,
    EC_PUT           = 2,
    EC_POST          = 3,
    EC_DELETE        = 4
} ec_method_t;

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

    EC_CLI_STATE_MAX = EC_CLI_STATE_REQ_RST
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
    EC_SRV_STATE_RESP_DONE          /* F */
} ec_srv_state_t;

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
