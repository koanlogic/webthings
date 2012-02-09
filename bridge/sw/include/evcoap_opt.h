#ifndef _EC_PRV_H_
#define _EC_PRV_H_

#include <u/libu.h>
#include <event2/util.h>

#include "kink_conf.h"
#include "evcoap_enums.h"

/* TODO take care of option delta and length fields overhead which should be
 * TODO a maximum of 4 bytes per option. */
#define EC_OPTS_MAX_LEN         (EC_COAP_MAX_OPTIONS * EC_COAP_OPT_LEN_MAX)

/* When introducing a new option, add a new symbol here and a corresponding
 * entry into the g_opts array. */
typedef enum
{
    EC_OPT_NONE = 0,
    
    EC_OPT_CONTENT_TYPE,
    EC_OPT_MAX_AGE,
    EC_OPT_PROXY_URI,
    EC_OPT_ETAG,
    EC_OPT_URI_HOST,
    EC_OPT_LOCATION_PATH,
    EC_OPT_URI_PORT,
    EC_OPT_LOCATION_QUERY,
    EC_OPT_URI_PATH,
    EC_OPT_OBSERVE,
    EC_OPT_TOKEN,
    EC_OPT_ACCEPT,
    EC_OPT_IF_MATCH,
    EC_OPT_URI_QUERY,
    EC_OPT_BLOCK2,
    EC_OPT_BLOCK1,
    EC_OPT_IF_NONE_MATCH,
    
    EC_OPT_MAX = EC_OPT_IF_NONE_MATCH + 1
} ec_opt_sym_t;
#define EC_OPT_SYM_VALID(sy) (sy > EC_OPT_NONE && sy < EC_OPT_MAX)

typedef enum
{
    EC_OPT_TYPE_INVALID,
    EC_OPT_TYPE_UINT,
    EC_OPT_TYPE_STRING,
    EC_OPT_TYPE_OPAQUE,
    EC_OPT_TYPE_EMPTY   /* No type (e.g. if-none-match) */
} ec_opt_type_t;

/* Maximum number of options that can be encoded in a single CoAP PDU. */
#define EC_PROTO_MAX_OPTIONS    15

struct ec_opt_s
{
    ec_opt_sym_t sym;
    ec_opt_type_t t;
    size_t l;
    uint8_t *v;

    TAILQ_ENTRY(ec_opt_s) next;
};


struct ec_opts_s
{
    uint8_t enc[EC_OPTS_MAX_LEN];
    size_t enc_sz;

    size_t noptions;
    TAILQ_HEAD(ec_opts, ec_opt_s) bundle;
};

typedef struct ec_opts_s ec_opts_t;
typedef struct ec_opt_s ec_opt_t;

ec_opt_t *ec_opt_new(ec_opt_sym_t sym, size_t l, const uint8_t *v);
void ec_opt_free(ec_opt_t *opt);
ec_opt_type_t ec_opt_sym2type(ec_opt_sym_t sym);
size_t ec_opt_sym2num(ec_opt_sym_t sym);
const char *ec_opt_sym2str(ec_opt_sym_t sym);
ec_opt_sym_t ec_opt_num2sym(size_t num);

int ec_opts_push(ec_opts_t *opts, ec_opt_t *o);
void ec_opts_clear(ec_opts_t *opts);
int ec_opts_init(ec_opts_t *opts);
int ec_opts_add(ec_opts_t *opts, ec_opt_sym_t sym, const uint8_t *v, 
        size_t l);
int ec_opts_add_empty(ec_opts_t *opts, ec_opt_sym_t sym);
int ec_opts_add_opaque(ec_opts_t *opts, ec_opt_sym_t sym, const uint8_t *v,
        size_t l);
int ec_opts_add_raw(ec_opts_t *opts, ec_opt_sym_t sym, const uint8_t *v,
        size_t l);
int ec_opts_add_string(ec_opts_t *opts, ec_opt_sym_t sym, const char *s);
int ec_opts_add_uint(ec_opts_t *opts, ec_opt_sym_t sym, uint64_t v);
int ec_opts_add_content_type(ec_opts_t *opts, uint16_t ct);
int ec_opts_add_max_age(ec_opts_t *opts, uint32_t ma);
int ec_opts_add_proxy_uri(ec_opts_t *opts, const char *pu);
int ec_opts_add_etag(ec_opts_t *opts, const uint8_t *et, size_t et_len);
int ec_opts_add_uri_host(ec_opts_t *opts, const char  *uh);
int ec_opts_add_location_path(ec_opts_t *opts, const char *lp);
int ec_opts_add_uri_port(ec_opts_t *opts, uint16_t up);
int ec_opts_add_location_query(ec_opts_t *opts, const char *lq);
int ec_opts_add_uri_path(ec_opts_t *opts, const char *up);
int ec_opts_add_token(ec_opts_t *opts, const uint8_t *t, size_t t_len);
int ec_opts_add_accept(ec_opts_t *opts, uint16_t a);
int ec_opts_add_if_match(ec_opts_t *opts, const uint8_t *im, size_t im_len);
int ec_opts_add_uri_query(ec_opts_t *opts, const char *uq);
int ec_opts_add_if_none_match(ec_opts_t *opts);
int ec_opts_add_observe(ec_opts_t *opts, uint16_t o);
int ec_opts_add_block1(ec_opts_t *opts, uint32_t num, bool more,
        uint8_t szx);
int ec_opts_add_block2(ec_opts_t *opts, uint32_t num, bool more,
        uint8_t szx);
ec_opt_t *ec_opts_get_nth(ec_opts_t *opts, ec_opt_sym_t sym, size_t n);
ec_opt_t *ec_opts_get(ec_opts_t *opts, ec_opt_sym_t sym);
const char *ec_opts_get_string(ec_opts_t *opts, ec_opt_sym_t sym);
const char *ec_opts_get_uri_host(ec_opts_t *opts);
int ec_opts_get_uri_port(ec_opts_t *opts, uint16_t *port);
int ec_opts_get_if_none_match(ec_opts_t *opts);
int ec_opts_get_accept_all(ec_opts_t *opts, ec_mt_t *mta, size_t *mta_sz);
int ec_opts_get_content_type(ec_opts_t *opts, uint16_t *ct);
uint8_t *ec_opts_get_etag_nth(ec_opts_t *opts, size_t *etag_sz, size_t n);
const char *ec_opts_get_proxy_uri(ec_opts_t *opts, char url[U_URI_STRMAX]);
int ec_opts_get_block1(ec_opts_t *opts, uint32_t *num, bool *more,
        uint8_t *szx);
int ec_opts_get_block2(ec_opts_t *opts, uint32_t *num, bool *more,
        uint8_t *szx);

int ec_opt_decode_uint(const uint8_t *v, size_t l, uint64_t *ui);
int ec_opt_encode_uint(uint64_t ui, uint8_t *e, size_t *elen);

int ec_opts_encode(ec_opts_t *opts);
ec_rc_t ec_opts_decode(ec_opts_t *opts, const uint8_t *pdu, size_t pdu_sz,
        uint8_t oc, size_t *olen);

u_uri_t *ec_opts_compose_url(ec_opts_t *opts, struct sockaddr_storage *us,
        bool nosec);

int ec_opts_count_sym(ec_opts_t *opts, ec_opt_sym_t sym, size_t *n);


#endif  /* !_EC_PRV_H_ */
