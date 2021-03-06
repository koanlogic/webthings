#ifndef _EC_RESOURCE_H_
#define _EC_RESOURCE_H_

#include <u/libu.h>

#include "evcoap_enums.h"
#include "evcoap_resource.h"
 
#ifndef EC_ETAG_SZ
  #define EC_ETAG_SZ  4
#endif  /* !EC_ETAG_SZ */

#ifndef EC_LINK_FMT_MAX
  #define EC_LINK_FMT_MAX 1024
#endif  /* !EC_LINK_FMT_MAX */

#ifndef EC_RES_ATTR_MAX
  #define EC_RES_ATTR_MAX   1024
#endif  /* !EC_RES_ATTR_MAX */

typedef struct ec_who_s
{
    bool is_set;
    struct sockaddr_storage peer;
    /* TODO strong identity credentials. */
} ec_who_t;

/* Resource representation with private attributes and data. */
typedef struct ec_rep_s
{
    ec_mt_t media_type;
    uint8_t etag[EC_ETAG_SZ];   /* Automatically computed at insert time. */
    uint8_t *data;
    size_t data_sz;
    struct ec_res_s *res;       /* Reference to parent resource. */
    TAILQ_ENTRY(ec_rep_s) next;
} ec_rep_t;

typedef struct ec_res_attrs_s
{
    bool obs, exp;                      /* obs and exp */
    char interface[EC_RES_ATTR_MAX];    /* if= */
    char res_type[EC_RES_ATTR_MAX];     /* rt= */
    /* XXX Resource size (sz=) depends on representation. */
    /* XXX Resource size (ct=) depends on representation. */
} ec_res_attrs_t;               

/* Resources may have multiple representations, each having their own media 
 * type. */
typedef struct ec_res_s
{
    char uri[EC_URI_MAX];
    ec_method_mask_t methods;   /* Bitfield of supported methods. */
    uint32_t max_age;
    ec_res_attrs_t attrs;
    time_t birth;               /* Creation timestamp. */
    ec_who_t creator;           /* Owner/creator Id */
    TAILQ_HEAD(, ec_rep_s) reps;
} ec_res_t;

/* Resource representation. */
ec_rep_t *ec_rep_new(ec_res_t *res, const ev_uint8_t *data, size_t data_sz, 
        ec_mt_t mt);
ec_res_t *ec_rep_get_res(ec_rep_t *rep);
void ec_rep_free(ec_rep_t *rep);
int ec_rep_del(ec_res_t *res, ec_rep_t *rep);

/* Resource. */
ec_res_t *ec_resource_new(const char *uri, ec_method_mask_t methods,
        uint32_t max_age);
void ec_resource_free(ec_res_t *res);
int ec_resource_add_rep(ec_res_t *res, const uint8_t *data, size_t data_sz, 
        ec_mt_t mt, uint8_t etag[EC_ETAG_SZ]);
int ec_resource_update_rep(ec_res_t *res, const uint8_t *data, size_t data_sz,
        ec_mt_t media_type, uint8_t etag[EC_ETAG_SZ]);
bool ec_resource_is_empty(ec_res_t *res);

/* Link formatter & friends. */
char *ec_res_link_format_str(const ec_res_t *res, const char *origin,
        const char *query, bool relative_ref, char lfs[EC_LINK_FMT_MAX]);

int ec_res_attrs_init(ec_res_t *res);

int ec_res_attrs_set_obs(ec_res_t *res, bool observable);
int ec_res_attrs_set_exp(ec_res_t *res, bool exportable);
int ec_res_attrs_set_if(ec_res_t *res, const char *interface);
int ec_res_attrs_set_rt(ec_res_t *res, const char *res_type);

int ec_res_attrs_get_obs(const ec_res_t *res, bool *observable);
int ec_res_attrs_get_exp(const ec_res_t *res, bool *exportable);
int ec_res_attrs_get_if(const ec_res_t *res, char interface[EC_RES_ATTR_MAX]);
int ec_res_attrs_get_rt(const ec_res_t *res, char res_type[EC_RES_ATTR_MAX]);

ec_rep_t *ec_resource_get_rep(ec_res_t *res, ec_mt_t mt, const uint8_t *etag);
ec_rep_t *ec_resource_get_suitable_rep(ec_res_t *res, ec_mt_t *mta,
        size_t mta_sz, const uint8_t *etag);
int ec_resource_check_method(ec_res_t *res, ec_method_t method);

#endif  /* !_EC_RESOURCE_H_ */
