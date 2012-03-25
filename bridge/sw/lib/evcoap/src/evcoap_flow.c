#include "evcoap_flow.h"

int ec_flow_init(ec_flow_t *flow)
{
    dbg_return_if (flow == NULL, -1);

    memset(flow, 0, sizeof *flow);
    flow->is_sep = false;
        
    (void) ec_conn_init(&flow->conn);

    return 0;
}

void ec_flow_term(ec_flow_t *flow)
{
    if (flow)
    {
        if (flow->uri)
           u_uri_free(flow->uri); 
        ec_conn_term(&flow->conn);
    }
    return;
}

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

int ec_flow_save_url(ec_flow_t *flow, u_uri_t *u, bool is_proxy)
{
    char saved_q[U_TOKEN_SZ];

    dbg_return_if (flow == NULL, -1);
    dbg_return_if (u == NULL, -1);

    /* Make a copy of the query string before clobbering the URI. */
    dbg_err_if (u_strlcpy(saved_q, u_uri_get_query(u), sizeof saved_q));

    /* Strip out query params for path matching. */
    (void) u_uri_set_query(u, "");

    /* Also save a string copy of the URL. */
    dbg_err_if (u_uri_knead(u, flow->urlstr));

    /* Restore query. */
    (void) u_uri_set_query(u, saved_q);

    flow->uri = u;
    flow->proxy_uri = is_proxy;

    return 0;
err:
    return -1;
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

int ec_flow_get_proxied(ec_flow_t *flow, bool *is_proxy)
{
    dbg_return_if (flow == NULL, -1);

    *is_proxy = flow->proxy_uri;

    return 0;
}

const char *ec_flow_get_url(ec_flow_t *flow, char url[U_URI_STRMAX],
        bool *is_proxy)
{
    dbg_return_if (flow == NULL, NULL);
    dbg_return_if (url == NULL, NULL);
    dbg_return_if (is_proxy == NULL, NULL);

    dbg_err_if (u_uri_knead(flow->uri, url));
    *is_proxy = flow->proxy_uri;

    return url;
err:
    return NULL;
}

int ec_flow_set_separate(ec_flow_t *flow, bool is_sep)
{
    dbg_return_if (flow == NULL, -1);

    flow->is_sep = is_sep;

    return 0;
}

int ec_flow_get_separate(ec_flow_t *flow, bool *is_sep)
{
    dbg_return_if (flow == NULL, -1);

    *is_sep = flow->is_sep;

    return 0;
}
