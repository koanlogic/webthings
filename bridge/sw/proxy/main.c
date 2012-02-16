#include <u/libu.h>
#include <evcoap.h>
#include <evhttp.h>

int facility = LOG_LOCAL0;

struct event_base *base;
struct evhttp *http;
struct evdns_base *dns;
ec_t *coap;

void process_http_request(struct evhttp_request *req, void *arg);
void process_coap_response(ec_client_t *cli);

int main(void)
{
    con_err_if ((base = event_base_new()) == NULL);
    con_err_if ((dns = evdns_base_new(base, 1)) == NULL);
    con_err_if ((coap = ec_init(base, dns)) == NULL);
    con_err_if ((http = evhttp_new(base)) == NULL);

    con_err_if (evhttp_bind_socket(http, "0.0.0.0", 5683));

    evhttp_set_gencb(http, process_http_request, NULL);
    event_base_dispatch(base);

    return EXIT_SUCCESS;
err:
    return EXIT_FAILURE;
}

void process_http_request(struct evhttp_request *req, void *arg)
{
    u_uri_t *u = NULL;
    const char *hpath = evhttp_request_uri(req);
    char huri[1024];
    char curi[U_URI_STRMAX];
    ec_client_t *ccli = NULL;
    struct timeval tout = { .tv_sec = 3, .tv_usec = 0 };

    (void) u_snprintf(huri, sizeof huri, "http://%s%s", 
            evhttp_find_header(req->input_headers, "Host"), hpath);

    u_con("requested URI: %s", huri);

    con_err_if (u_uri_crumble(huri, 0, &u));

    /* URI map is just a scheme substitution. */
    (void) u_uri_set_scheme(u, "coap");
    (void) u_uri_set_host(u, "zrs");

    con_err_if (u_uri_knead(u, curi));

    u_con("mapped URI: %s", curi);

    con_err_if ((ccli = ec_request_new(coap, EC_GET, curi, EC_CON)) == NULL);
    con_err_if (ec_request_send(ccli, process_coap_response, req, &tout));

    u_uri_free(u);

    return;
err:
    if (u)
        u_uri_free(u);
    if (ccli)
        ec_client_free(ccli);
    return;
}

void process_coap_response(ec_client_t *cli)
{
    ec_rc_t rc;
    ec_cli_state_t s;
    ev_uint8_t *pl;
    char payload[1024] = { '\0' };
    size_t pl_sz;
    struct evbuffer *buf = NULL;
    struct evhttp_request *req = (struct evhttp_request *) cli->cb_args;

    con_err_ifm ((s = ec_client_get_state(cli)) != EC_CLI_STATE_REQ_DONE,
            "request failed: %s", ec_cli_state_str(s));

    /* Get response code. */
    con_err_ifm ((rc = ec_response_get_code(cli)) == EC_RC_UNSET,
            "could not get response code");

    if (rc == EC_CONTENT)
    {
        con_err_ifm ((pl = ec_response_get_payload(cli, &pl_sz)) == NULL,
                "empty payload");
        strncpy(payload, (const char *) pl, U_MIN(sizeof payload, pl_sz));
        payload[pl_sz] = '\0';
    }

    con_err_if ((buf = evbuffer_new()) == NULL);

    evhttp_add_header(evhttp_request_get_output_headers(req), 
            "Content-Type", "text/plain; charset=UTF-8");

    evbuffer_add_printf(buf, "%s", payload);

    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);

    return;
err:
    if (buf)
        evbuffer_free(buf);
    evhttp_send_reply(req, HTTP_INTERNAL, "wtf!", NULL);
}
