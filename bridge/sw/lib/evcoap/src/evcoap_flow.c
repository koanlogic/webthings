#include "evcoap_flow.h"

int ec_flow_save_token(ec_flow_t *flow, ev_uint8_t *tok, size_t tok_sz)
{
    dbg_return_if (flow == NULL, -1);

    if (tok == NULL || tok_sz == 0)
    {
        memset(flow->token, 0, sizeof flow->token);
        flow->token_sz = 0;
    }
    else
    {
        memcpy(flow->token, tok, tok_sz); 
        flow->token_sz = tok_sz;
    }

    return 0;
}

int ec_flow_save_url(ec_flow_t *flow, u_uri_t *url)
{
    dbg_return_if (flow == NULL, -1);
    dbg_return_if (url == NULL, -1);

    /* Also save a string copy of the URL. */
    dbg_return_if (u_uri_knead(url, flow->urlstr), -1);
    flow->uri = url;

    return 0;
}

int ec_flow_get_token(ec_flow_t *flow, ev_uint8_t token[8], size_t *token_sz)
{
    dbg_return_if (flow == NULL, -1);
    dbg_return_if (token == NULL, -1);
    dbg_return_if (token_sz == NULL, -1);

    if (flow->token_sz == 0)
        goto end;

    memcpy(token, flow->token, flow->token_sz);

    /* Fall through. */
end:
    *token_sz = flow->token_sz;
    return 0;
}

const char *ec_flow_get_urlstr(ec_flow_t *flow)
{
    dbg_return_if (flow == NULL, NULL);

    return flow->urlstr;
}

ec_method_t ec_flow_get_method(ec_flow_t *flow)
{
    dbg_return_if (flow == NULL, EC_METHOD_UNSET);

    return flow->method;
}

int ec_flow_set_method(ec_flow_t *flow, ec_method_t method)
{
    dbg_return_if (flow == NULL, -1);
    dbg_return_if (!EC_IS_METHOD(method), -1);

    flow->method = method;

    return 0;
}

int ec_flow_set_resp_code(ec_flow_t *flow, ec_rc_t rc)
{
    dbg_return_if (flow == NULL, -1);
    dbg_return_if (!EC_IS_RESP_CODE(rc), -1);

    flow->resp_code = rc;

    return 0;
}

ec_rc_t ec_flow_get_resp_code(ec_flow_t *flow)
{
    dbg_return_if (flow == NULL, EC_RC_UNSET);

    return flow->resp_code;
}