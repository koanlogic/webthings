#include "evcoap_flow.h"

int ec_flow_save_token(ec_flow_t *flow, const uint8_t *tok, size_t tok_sz)
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

    /* Strip out query params for path matching. */
    dbg_return_if (u_uri_set_query(url, ""), -1);

    /* Also save a string copy of the URL. */
    dbg_return_if (u_uri_knead(url, flow->urlstr), -1);
    flow->uri = url;

    return 0;
}

int ec_flow_get_token(ec_flow_t *flow, uint8_t token[8], size_t *token_sz)
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

u_uri_t *ec_flow_get_uri(ec_flow_t *flow)
{
    dbg_return_if (flow == NULL, NULL);

    return flow->uri;
}

const char *ec_flow_get_uri_origin(ec_flow_t *flow)
{
    dbg_return_if (flow == NULL, NULL);

    char *o = flow->origin;
    const size_t o_sz = sizeof flow->origin;

    /* Compute and cache the origin value. */
    if (o[0] == '\0')
    {
        u_uri_t *u = flow->uri;
        u_uri_flags_t f = u_uri_get_flags(u);

        dbg_err_if (u == NULL);
        
        dbg_err_if (u_strlcpy(o, u_uri_get_scheme(u), o_sz));
        dbg_err_if (u_strlcat(o, "://", o_sz));

        if (f & U_URI_FLAGS_HOST_IS_IPLITERAL)
            dbg_err_if (u_strlcat(o, "[", o_sz));

        dbg_err_if (u_strlcat(o, u_uri_get_host(u), o_sz));

        if (f & U_URI_FLAGS_HOST_IS_IPLITERAL)
            dbg_err_if (u_strlcat(o, "]", o_sz));

        dbg_err_if (u_strlcat(o, ":", o_sz));
        dbg_err_if (u_strlcat(o, u_uri_get_port(u), o_sz));
    }

    return flow->origin;
err:
    return NULL;
}

const char *ec_flow_get_uri_query(ec_flow_t *flow)
{
    dbg_return_if (flow == NULL, NULL);

    return u_uri_get_query(flow->uri);
}

const char *ec_flow_get_uri_path(ec_flow_t *flow)
{
    dbg_return_if (flow == NULL, NULL);

    return u_uri_get_path(flow->uri);
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
