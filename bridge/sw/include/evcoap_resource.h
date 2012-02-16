#ifndef _EC_RESOURCE_H_
#define _EC_RESOURCE_H_

#include <u/libu.h>

#include "evcoap_enums.h"
#include "evcoap_resource.h"
 
#define EC_ETAG_SZ  4

/* Resource representation with private attributes and data. */
typedef struct ec_rep_s
{
    ec_mt_t media_type;
    uint8_t etag[EC_ETAG_SZ];   /* Automatically computed at insert time. */
    uint8_t *data;
    size_t data_sz;
    uint32_t max_age;           /* Cloned from the parent resource. */
    TAILQ_ENTRY(ec_rep_s) next;
} ec_rep_t;

/* Resources may have multiple representations, each having their own media 
 * type. */
typedef struct ec_res_s
{
    char uri[EC_URI_MAX];
    uint32_t max_age;
    TAILQ_HEAD(, ec_rep_s) reps;
} ec_res_t;

/* Resource representation. */
ec_rep_t *ec_rep_new(const ev_uint8_t *data, size_t data_sz, ec_mt_t mt);
void ec_rep_free(ec_rep_t *rep);

/* Resource. */
ec_res_t *ec_resource_new(const char *uri, uint32_t max_age);
void ec_resource_free(ec_res_t *res);
int ec_resource_add_rep(ec_res_t *res, const uint8_t *data, size_t data_sz, 
        ec_mt_t mt, uint8_t etag[EC_ETAG_SZ]);

ec_rep_t *ec_resource_get_rep(ec_res_t *res, const char *uri, ec_mt_t mt, 
        const uint8_t *etag);
ec_rep_t *ec_resource_get_suitable_rep(ec_res_t *res, const char *uri,
        ec_mt_t *mta, size_t mta_sz, const uint8_t *etag);

#endif  /* !_EC_RESOURCE_H_ */
