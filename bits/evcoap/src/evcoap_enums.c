#include <u/libu.h>
#include "evcoap_enums.h"

static const char *g_client_states[] =
{
    [EC_CLI_STATE_NONE]         = "null state",
    [EC_CLI_STATE_DNS_FAILED]   = "DNS failed (FINAL)",
    [EC_CLI_STATE_DNS_OK]       = "DNS succeeded",
    [EC_CLI_STATE_SEND_FAILED]  = "request PDU send failed (FINAL)",
    [EC_CLI_STATE_REQ_SENT]     = "request PDU send succeeded",
    [EC_CLI_STATE_REQ_ACKD]     = "request PDU acknowledged (separate message)",
    [EC_CLI_STATE_APP_TIMEOUT]  = "application timeout elapsed (FINAL)",
    [EC_CLI_STATE_COAP_RETRY]   = "request PDU in retransmission",
    [EC_CLI_STATE_COAP_TIMEOUT] = "protocol timeout elapsed (FINAL)",
    [EC_CLI_STATE_REQ_DONE]     = "response received (FINAL)",
    [EC_CLI_STATE_REQ_RST]      = "request PDU reset by server (FINAL)"
};

const char *ec_cli_state_str(ec_cli_state_t s)
{
    if (s > EC_CLI_STATE_MAX)
        return "unknown state";

    return g_client_states[s];
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
