#ifndef _EC_H_
#define _EC_H_

#include <stdbool.h>
#include <event2/util.h>

#include "kink_conf.h"
#include "evcoap_enums.h"
#include "evcoap_base.h"
#include "evcoap_flow.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

/* 
 * Setup / Teardown / Control.
 */
ec_t *ec_init(struct event_base *base, struct evdns_base *dns);
void ec_term(ec_t *coap);

int ec_loopbreak(ec_t *coap);
int ec_loopexit(ec_t *coap, const struct timeval *tv);

/* Global configuration parameters. */
int ec_set_block_size(ec_t *coap, size_t val);
int ec_get_block_size(ec_t *coap, size_t *val);

/* 
 * Client API
 */
ec_client_t *ec_request_new(ec_t *coap, ec_method_t m, const char *uri, 
        ec_msg_model_t mm);

ec_client_t *ec_proxy_request_new(ec_t *coap, ec_method_t m, const char *uri,
        ec_msg_model_t mm, const char *proxy_host, uint16_t proxy_port);

ec_client_t *ec_observe_new(ec_t *coap, const char *uri, ec_msg_model_t mm);

ec_client_t *ec_proxy_observe_new(ec_t *coap, const char *uri, 
        ec_msg_model_t mm, const char *proxy_host, uint16_t proxy_port);

int ec_request_send(ec_client_t *cli, ec_client_cb_t cb, void *cb_args,
        struct timeval *tout);

/* Server API */
int ec_bind_socket(ec_t *coap, const char *addr, uint16_t port);

int ec_register_cb(ec_t *coap, const char *url, ec_server_cb_t cb, void *args);
int ec_register_fb(ec_t *coap, ec_server_cb_t cb, void *cb_args);
int ec_unregister_cb(ec_t *coap, const char *url);
int ec_unregister_fb(ec_t *coap);

/* PDU manipulation API */
int ec_request_set_payload(ec_client_t *cli, const uint8_t *payload, size_t sz);

int ec_request_add_block1(ec_client_t *cli, uint32_t bnum, bool more,
        size_t bsz);
int ec_request_add_block2(ec_client_t *cli, uint32_t bnum, bool more,
        size_t bsz);
int ec_request_add_observe(ec_client_t *cli);

int ec_request_add_content_type(ec_client_t *cli, uint16_t ct);
int ec_request_add_max_age(ec_client_t *cli, uint32_t ma);
int ec_request_add_proxy_uri(ec_client_t *cli, const char *pu);
int ec_request_add_etag(ec_client_t *cli, const uint8_t *et, size_t et_len);
int ec_request_add_uri_host(ec_client_t *cli, const char  *uh);
int ec_request_add_location_path(ec_client_t *cli, const char *lp);
int ec_request_add_uri_port(ec_client_t *cli, uint16_t up);
int ec_request_add_location_query(ec_client_t *cli, const char *lq);
int ec_request_add_uri_path(ec_client_t *cli, const char *up);
int ec_request_add_token(ec_client_t *cli, const uint8_t *t, size_t t_len);
int ec_request_add_accept(ec_client_t *cli, uint16_t a);
int ec_request_add_if_match(ec_client_t *cli, const uint8_t *im, 
        size_t im_len);
int ec_request_add_uri_query(ec_client_t *cli, const char *uq);
int ec_request_add_if_none_match(ec_client_t *cli);
int ec_request_add_observe(ec_client_t *cli);
int ec_request_add_publish(ec_client_t *cli, ec_method_mask_t allowed_methods);

bool ec_request_via_proxy(ec_server_t *srv);

ec_rc_t ec_response_get_code(ec_client_t *cli);
int ec_response_get_content_type(ec_client_t *cli, ec_mt_t *ct);
int ec_response_get_block1(ec_client_t *cli, uint32_t *bnum, bool *more,
        size_t *bsz);
int ec_response_get_block2(ec_client_t *cli, uint32_t *bnum, bool *more,
        size_t *bsz);
int ec_response_get_observe(ec_client_t *cli, uint16_t *o);
int ec_response_get_max_age(ec_client_t *cli, uint32_t *max_age);

int ec_request_get_if_none_match(ec_server_t *srv);
int ec_request_get_publish(ec_server_t *srv, ec_method_mask_t *allowed_methods);
int ec_request_get_max_age(ec_server_t *srv, uint32_t *max_age);

uint8_t *ec_response_get_payload(ec_client_t *cli, size_t *sz);

uint8_t *ec_request_get_payload(ec_server_t *srv, size_t *sz);
int ec_request_get_observe(ec_server_t *srv);
int ec_request_get_block1(ec_server_t *srv, uint32_t *bnum, bool *more,
        size_t *bsz);
int ec_request_get_block2(ec_server_t *srv, uint32_t *bnum, bool *more,
        size_t *bsz);
int ec_request_get_acceptable_media_types(ec_server_t *srv, ec_mt_t *mta,
        size_t *mta_sz);
int ec_request_get_content_type(ec_server_t *srv, ec_mt_t *mt);

const char *ec_request_get_uri_origin(ec_server_t *srv);
const char *ec_request_get_uri_query(ec_server_t *srv);
const char *ec_request_get_uri_path(ec_server_t *srv);
const char *ec_request_get_uri(ec_server_t *srv, char uri[U_URI_STRMAX],
        bool *is_proxy);

int ec_response_set_payload(ec_server_t *srv, const uint8_t *pload, size_t sz);
int ec_response_set_code(ec_server_t *srv, ec_rc_t rc);
int ec_response_add_etag(ec_server_t *srv, const uint8_t *et, size_t et_len);
int ec_response_add_content_type(ec_server_t *srv, uint16_t ct);
int ec_response_add_max_age(ec_server_t *srv, uint32_t max_age);
int ec_response_add_observe(ec_server_t *srv, uint16_t o);
int ec_response_add_block1(ec_server_t *srv, uint32_t bnum, bool more,
        size_t bsz);
int ec_response_add_block2(ec_server_t *srv, uint32_t bnum, bool more,
        size_t bsz);
int ec_response_add_location_path(ec_server_t *srv, const char *lp);
int ec_response_add_location_query(ec_server_t *srv, const char *lq);

/* Observe API */
int ec_update_representation(const char *uri, const uint8_t *rep,
        size_t rep_len, ec_mt_t media_type);

int ec_get_observe_counter(uint16_t *cnt);

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif  /* !_EC_H_ */
