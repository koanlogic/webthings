#include <strings.h>
#include <u/libu.h>
#include "evcoap_enums.h"

static const char *g_client_states[] =
{
    [EC_CLI_STATE_NONE]         = "NULL STATE",
    [EC_CLI_STATE_INTERNAL_ERR] = "INTERNAL ERR (FINAL)",
    [EC_CLI_STATE_DNS_FAILED]   = "DNS FAILED (FINAL)",
    [EC_CLI_STATE_DNS_OK]       = "DNS OK",
    [EC_CLI_STATE_SEND_FAILED]  = "SEND FAILED (FINAL)",
    [EC_CLI_STATE_REQ_SENT]     = "REQ SENT",
    [EC_CLI_STATE_REQ_ACKD]     = "REQ ACKD (separate message)",
    [EC_CLI_STATE_APP_TIMEOUT]  = "APP TIMEOUT (FINAL)",
    [EC_CLI_STATE_COAP_RETRY]   = "COAP RETRY",
    [EC_CLI_STATE_COAP_TIMEOUT] = "COAP TIMEOUT (FINAL)",
    [EC_CLI_STATE_REQ_DONE]     = "REQ DONE (FINAL)",
    [EC_CLI_STATE_REQ_RST]      = "REQ RST (FINAL)",
    [EC_CLI_STATE_WAIT_NFY]     = "WAIT NOTIFICATION",
    [EC_CLI_STATE_OBS_TIMEOUT]  = "OBSERVE TIMEOUT (FINAL)"
};

const char *ec_cli_state_str(ec_cli_state_t s)
{
    if (s > EC_CLI_STATE_MAX)
        return "unknown state";

    return g_client_states[s];
}

ec_method_mask_t ec_method_to_mask(ec_method_t method)
{
    switch (method)
    {
        case EC_GET:
            return EC_GET_MASK;
        case EC_PUT:
            return EC_PUT_MASK;
        case EC_POST:
            return EC_POST_MASK;
        case EC_DELETE:
            return EC_DELETE_MASK;
        case EC_METHOD_UNSET:
        case EC_METHOD_MAX:
        default:
            return -1;
    }
}

int ec_mt_from_string(const char *s, ec_mt_t *pmt)
{
    int rc = 0;

    dbg_return_if (s == NULL || *s == '\0', -1);

    if (!strcasecmp(s, "text/plain"))
        *pmt = EC_MT_TEXT_PLAIN;
    else if (!strcasecmp(s, "application/link-format"))
        *pmt = EC_MT_APPLICATION_LINK_FORMAT;
    else if (!strcasecmp(s, "application/xml"))
        *pmt = EC_MT_APPLICATION_XML;
    else if (!strcasecmp(s, "application/octet-stream"))
        *pmt = EC_MT_APPLICATION_OCTET_STREAM;
    else if (!strcasecmp(s, "application/exi"))
        *pmt = EC_MT_APPLICATION_EXI;
    else if (!strcasecmp(s, "application/json"))
        *pmt = EC_MT_APPLICATION_JSON;
    else
    {
        u_dbg("unknown media type %s", s); 
        rc = -1;
    }

    return rc;
}

static const char *g_server_states[] =
{
    [EC_SRV_STATE_NONE]             = "NULL STATE",
    [EC_SRV_STATE_INTERNAL_ERR]     = "INTERNAL ERR (FINAL)",
    [EC_SRV_STATE_DUP_REQ]          = "DUP REQ (FINAL)",
    [EC_SRV_STATE_BAD_REQ]          = "BAD REQ (FINAL)",
    [EC_SRV_STATE_REQ_OK]           = "REQ OK",
    [EC_SRV_STATE_ACK_SENT]         = "ACK SENT",
    [EC_SRV_STATE_WAIT_ACK]         = "WAIT ACK",
    [EC_SRV_STATE_RESP_ACK_TIMEOUT] = "ACK TIMEDOUT",
    [EC_SRV_STATE_RESP_DONE]        = "RESP DONE"
};

const char *ec_srv_state_str(ec_srv_state_t s)
{
    if (s > EC_SRV_STATE_MAX)
        return "unknown state";

    return g_server_states[s];
}

const char *ec_rc_str(ec_rc_t rc)
{
    switch (rc)
    {
        case EC_CREATED:
            return "2.01 (Created)";
        case EC_DELETED:
            return "2.02 (Deleted)";
        case EC_VALID:
            return "2.03 (Valid)";
        case EC_CHANGED:
            return "2.04 (Changed)";
        case EC_CONTENT:
            return "2.05 (Content)";

        case EC_BAD_REQUEST:
            return "4.00 (Bad Request)";
        case EC_UNAUTHORIZED:
            return "4.01 (Unauthorized)";
        case EC_BAD_OPTION:
            return "4.02 (Bad Option)";
        case EC_FORBIDDEN:
            return "4.03 (Forbidden)";
        case EC_NOT_FOUND:
            return "4.04 (Not Found)";
        case EC_METHOD_NOT_ALLOWED:
            return "4.05 (Method Not Allowed)";
        case EC_NOT_ACCEPTABLE:
            return "4.06 (Not Acceptable)";
        case EC_PRECONDITION_FAILED:
            return "4.12 (Precondition Failed)";
        case EC_REQUEST_ENTITY_TOO_LARGE:
            return "4.13 (Request Entity Too Large)";
        case EC_UNSUPPORTED_MEDIA_TYPE:
            return "4.15 (Unsupported Media Type)";

        case EC_INTERNAL_SERVER_ERROR:
            return "5.00 (Internal Server Error)";
        case EC_NOT_IMPLEMENTED:
            return "5.01 (Not Implemented)";
        case EC_BAD_GATEWAY:
            return "5.02 (Bad Gateway)";
        case EC_SERVICE_UNAVAILABLE:
            return "5.03 (Service Unavailable)";
        case EC_GATEWAY_TIMEOUT:
            return "5.04 (Gateway Timeout)";
        case EC_PROXYING_NOT_SUPPORTED:
            return "5.05 (Proxying Not Supported)";
        
        case EC_RC_UNSET:
        case EC_200_UNKNOWN:
        case EC_400_UNKNOWN:
        case EC_500_UNKNOWN:
        default:
            break;
    }

    if (rc == EC_RC_UNSET)
        return "response code unset";
    else if (rc <= EC_200_UNKNOWN)
        return "unknown success code";
    else if (rc <= EC_400_UNKNOWN)
        return "unknown client failure";
    else if (rc <= EC_500_UNKNOWN)
        return "unknown server failure";

    return "unknown response code";
}
