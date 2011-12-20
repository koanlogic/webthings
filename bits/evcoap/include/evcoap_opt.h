#ifndef _EC_PRV_H_
#define _EC_PRV_H_

#include <event2/util.h>

#include "evcoap_enums.h"

#define EC_OPT_LEN_MAX  270

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
    EC_OPT_MAX_OFE,
    EC_OPT_URI_QUERY,
    EC_OPT_IF_NONE_MATCH,
    
    EC_OPT_MAX = EC_OPT_IF_NONE_MATCH + 1
} ec_opt_t;
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
    ec_opt_t sym;
    ec_opt_type_t t;
    size_t l;
    ev_uint8_t *v;

    TAILQ_ENTRY(ec_opt_s) next;
};

struct ec_opts_s
{
    ev_uint8_t *enc;
    size_t enc_sz;

    size_t noptions;
    TAILQ_HEAD(ec_opts, ec_opt_s) bundle;
};

struct ec_opt_s *ec_opt_new(ec_opt_t sym, size_t l, const ev_uint8_t *v);
void ec_opt_free(struct ec_opt_s *opt);
ec_opt_type_t ec_opt_sym2type(ec_opt_t sym);
int ec_opt_add(struct ec_opts_s *opts, ec_opt_t sym, const ev_uint8_t *v, 
        size_t l);
int ec_opt_add_empty(struct ec_opts_s *opts, ec_opt_t sym);
int ec_opt_add_opaque(struct ec_opts_s *opts, ec_opt_t sym, const ev_uint8_t *v,
        size_t l);
int ec_opt_add_raw(struct ec_opts_s *opts, ec_opt_t sym, const ev_uint8_t *v,
        size_t l);
int ec_opt_add_string(struct ec_opts_s *opts, ec_opt_t sym, const char *s);
int ec_opt_add_uint(struct ec_opts_s *opts, ec_opt_t sym, ev_uint64_t v);
int ec_opt_encode_uint(ev_uint64_t ui, ev_uint8_t *e, size_t *elen);
int ec_opt_push(struct ec_opts_s *opts, struct ec_opt_s *o);

#endif  /* !_EC_PRV_H_ */
