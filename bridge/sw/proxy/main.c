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
    (void) u_uri_set_host(u, "127.0.0.1");

    con_err_if (u_uri_knead(u, g_ctx.curi));

    u_con("mapped URI: %s", g_ctx.curi);


    switch (req->type)
      {
    		case EVHTTP_REQ_GET:
    		    con_err_if ((g_ctx.cli = ec_request_new(g_ctx.coap, EC_COAP_GET,
    		                    g_ctx.curi, EC_COAP_CON)) == NULL);
    		    break;
    		case EVHTTP_REQ_PUT:
    		{

    			printf("1\n");
    		    struct evbuffer *body = evhttp_request_get_input_buffer(req);
    		    const char *ct = evhttp_find_header(evhttp_request_get_input_headers(req), "Content-Type");

    		    int len = evbuffer_get_length(body);

                char *tmp = malloc(len+1);
    		    memcpy(tmp, evbuffer_pullup(body, -1), len);
    		    tmp[len] = '\0';
printf("HTTP Payload %s\n", tmp);
printf("HTTP Content-Type %s\n", ct);
    		    con_err_if ((g_ctx.cli = ec_request_new(g_ctx.coap, EC_COAP_PUT,
    		                    g_ctx.curi, EC_COAP_CON)) == NULL);

    		    //set payload
    		    ec_request_set_payload(g_ctx.cli,tmp,len);

    		    //set Content-Type
    		    ec_request_add_content_type(g_ctx.cli, ct);
    		    free(tmp);
    		}
    		    break;
    		case EVHTTP_REQ_DELETE:
    		    con_err_if ((g_ctx.cli = ec_request_new(g_ctx.coap, EC_COAP_DELETE,
    		                    g_ctx.curi, EC_COAP_CON)) == NULL);
    		    break;
            default:
                break;
      }


	/* Add token option to allow for concurrent requests. */
   //con_err_if (ec_request_add_token(g_ctx.cli, NULL, 0));

    con_err_if (ec_request_send(g_ctx.cli, process_coap_response, req,
                &g_ctx.tout));


    u_uri_free(u);

    return;
err:
    if (u)
        u_uri_free(u);
    if (g_ctx.cli)
        ec_client_free(g_ctx.cli);
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

     u_con("%s", ec_rc_str((rc = ec_response_get_code(cli))));

     switch (rc)
       {
         case EC_CHANGED:
         case EC_DELETED:
        	     /*A successful response SHOULD be
        	      * 200 (OK) if the response includes an representation describing the status,
        	      * 202 (Accepted) if the action has not yet been enacted,
        	      * 204 (No Content) if the action has been enacted but the response does not include a representation.*/
        	    //To Do: Check all the cases!!
        	   evhttp_send_reply(req, HTTP_NOCONTENT, "No Content", g_ctx.buf);
        	   return;
           case	EC_CREATED:
        	   //return "2.01 (Created)"
        	   /*
        	    * ToDO: HTTP_CREATED does not exist in evhttp.h ???
        	    */
        	   evhttp_send_reply(req, 201, "Created", g_ctx.buf);
           case EC_CONTENT:
               //return "2.05 (Content)";
           break;
           case EC_NOT_FOUND:
           {
           //4.04 (Not Found)
           evhttp_send_reply(req, HTTP_NOTFOUND, "Not Found", g_ctx.buf);
           return;
           }
           case EC_METHOD_NOT_ALLOWED:
           {
        	   //4.05 (Method Not Allowed)
        	   evhttp_send_reply(req, HTTP_BADMETHOD, "Method Not Allowed", g_ctx.buf);
        	   return;
           }
           case EC_NOT_IMPLEMENTED:
           {
        	   //4.05 (Method Not Allowed)
        	   evhttp_send_reply(req, HTTP_NOTIMPLEMENTED, "Not Implemented", g_ctx.buf);
        	   return;
           }
           default:
               break;

       }


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
                     g_ctx.curi, EC_COAP_CON)) == NULL);
     con_err_if (ec_request_add_block2(g_ctx.cli, ++g_ctx.bopt.block_no, 0,
                 g_ctx.bopt.block_sz) == -1);
     con_err_if (ec_request_send(g_ctx.cli, process_coap_response, req,
                 &g_ctx.tout));
    return;
err:
    evhttp_send_reply(req, HTTP_INTERNAL, "wtf!", NULL);
}
