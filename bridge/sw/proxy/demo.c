#include <u/libu.h>
#include <evcoap.h>
#include <evhttp.h>

int facility = LOG_LOCAL0;

typedef struct
{
    uint32_t block_no;
    bool more;
    size_t block_sz;
} blockopt_t;

typedef struct
{
    ec_t *coap;
    ec_client_t *cli;
    char curi[U_URI_STRMAX];
    struct event_base *base;
    struct evdns_base *dns;
    struct evhttp *http;
    struct evbuffer *buf;
    blockopt_t bopt;
    struct timeval tout;
} ctx_t;

ctx_t g_ctx = {
    .coap = NULL,
    .cli = NULL,
    .curi = "\0",
    .base = NULL,
    .dns = NULL,
    .http = NULL,
    .buf = NULL,
    .bopt = { 0, 0, 0 },
    .tout = { .tv_sec = 3, .tv_usec = 0 }
};

void process_http_request(struct evhttp_request *req, void *arg);
void process_coap_response(ec_client_t *cli);

int main(void)
{
    con_err_if ((g_ctx.base = event_base_new()) == NULL);
    con_err_if ((g_ctx.dns = evdns_base_new(g_ctx.base, 1)) == NULL);
    con_err_if ((g_ctx.coap = ec_init(g_ctx.base, g_ctx.dns)) == NULL);
    con_err_if ((g_ctx.http = evhttp_new(g_ctx.base)) == NULL);

    con_err_if (evhttp_bind_socket(g_ctx.http, "0.0.0.0", 5683));

    evhttp_set_gencb(g_ctx.http, process_http_request, NULL);
    event_base_dispatch(g_ctx.base);

    return EXIT_SUCCESS;
err:
    return EXIT_FAILURE;
}

void process_http_request(struct evhttp_request *req, void *arg)
{
    const char *hpath;
    char huri[1024];
    u_uri_t *u = NULL;

    con_err_if (req == NULL);
    u_unused_args(arg);

    /* Per-round initialisations. */
    g_ctx.bopt.block_no = 0;
    g_ctx.bopt.more = 0;
    g_ctx.bopt.block_sz = 0;

    g_ctx.curi[0] = '\0';

    if (g_ctx.buf)
        evbuffer_free(g_ctx.buf);
    con_err_if ((g_ctx.buf = evbuffer_new()) == NULL);

    hpath = evhttp_request_uri(req);

    (void) u_snprintf(huri, sizeof huri, "http://%s%s",
            evhttp_find_header(req->input_headers, "Host"), hpath);

    u_con("requested URI: %s", huri);

    con_err_if (u_uri_crumble(huri, 0, &u));

    /* URI map is just a scheme substitution. */
    (void) u_uri_set_scheme(u, "coap");
    (void) u_uri_set_host(u, "zrs");

    con_err_if (u_uri_knead(u, g_ctx.curi));

    u_con("mapped URI: %s", g_ctx.curi);

    con_err_if ((g_ctx.cli = ec_request_new(g_ctx.coap, EC_COAP_GET,
                    g_ctx.curi, EC_COAP_CON, false)) == NULL);

	/* Add token option to allow for concurrent requests. */
	con_err_if (ec_request_add_token(g_ctx.cli, NULL, 0));

    con_err_if (ec_request_send(g_ctx.cli, process_coap_response, req,
                &g_ctx.tout));

    u_uri_free(u);

    return;
err:
    if (u)
        u_uri_free(u);
    return;
}

void process_coap_response(ec_client_t *cli)
{
    ec_rc_t rc;
    ec_cli_state_t s;
    ev_uint8_t *pl;
    ev_uint32_t bnum;

    char payload[1024] = { '\0' };
    size_t pl_sz;
    struct evhttp_request *req = (struct evhttp_request *) cli->cb_args;

    con_err_if (cli == NULL);

    con_err_ifm ((s = ec_client_get_state(cli)) != EC_CLI_STATE_REQ_DONE,
            "request failed: %s", ec_cli_state_str(s));

    /* Get response code. */
    con_err_ifm ((rc = ec_response_get_code(cli)) == EC_RC_UNSET,
            "could not get response code");

    /* If fragmented will set g_ctx.bopt. */
    if (ec_response_get_block2(cli, &bnum, &g_ctx.bopt.more,
                &g_ctx.bopt.block_sz) == 0) {

            /* Blockwise transfer - make sure requested block was returned. */
            con_err_if (bnum != g_ctx.bopt.block_no);

            g_ctx.bopt.block_no = bnum;
    }

    if (rc == EC_CONTENT)
    {
        con_err_ifm ((pl = ec_response_get_payload(cli, &pl_sz)) == NULL,
                "empty payload");
        strncpy(payload, (const char *) pl, U_MIN(sizeof payload, pl_sz));
        payload[pl_sz] = '\0';
    }

    evhttp_add_header(evhttp_request_get_output_headers(req),
            "Content-Type", "text/plain; charset=UTF-8");
    evhttp_add_header(evhttp_request_get_output_headers(req),
            "Access-Control-Allow-Origin", "*");
    evhttp_add_header(evhttp_request_get_output_headers(req),
            "Cache-Control", "no-cache");

    evbuffer_add_printf(g_ctx.buf, "%s", payload);

    /* No more blocks => send reply. */
    if (!g_ctx.bopt.more)
    {
        evhttp_send_reply(req, HTTP_OK, "OK", g_ctx.buf);
        return;
    }

    /* If there is more, send a new request with Block2 Option. */
    con_err_if ((g_ctx.cli = ec_request_new(g_ctx.coap, EC_COAP_GET,
                    g_ctx.curi, EC_COAP_CON, false)) == NULL);
    con_err_if (ec_request_add_block2(g_ctx.cli, ++g_ctx.bopt.block_no, 0,
                g_ctx.bopt.block_sz) == -1);
    con_err_if (ec_request_send(g_ctx.cli, process_coap_response, req,
                &g_ctx.tout));
    return;
err:
    evhttp_send_reply(req, HTTP_INTERNAL, "wtf!", NULL);
}
