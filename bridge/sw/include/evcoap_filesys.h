#ifndef _EC_FS_H_
#define _EC_FS_H_

#include <event2/util.h>
#include <u/libu.h>

#include "evcoap_enums.h"
 
#define EC_URI_MAX  512 /* XXX make it consistent with ec_res_t */
#define EC_ETAG_SZ  4

/* The filesys is just a wrapper around libu's hmap. */
typedef struct ec_filesys_s { u_hmap_t *map; } ec_filesys_t;

/* Resource representation with private attributes and data. */
typedef struct ec_filesys_rep_s
{
    ec_mt_t media_type;
    ev_uint8_t etag[EC_ETAG_SZ]; /* Automatically computed at insert time. */
    ev_uint8_t *data;
    size_t data_sz;
    TAILQ_ENTRY(ec_filesys_rep_s) next;
} ec_filesys_rep_t;

/* Resources may have multiple representations, each having their own media 
 * type. */
typedef struct ec_filesys_res_s
{
    char uri[EC_URI_MAX];
    ev_uint32_t max_age;
    TAILQ_HEAD(, ec_filesys_rep_s) reps;
} ec_filesys_res_t;

/* File system (basically: you add resources and get representations back.) */
ec_filesys_t *ec_filesys_create(void);
void ec_filesys_destroy(ec_filesys_t *fs);
int ec_filesys_put_resource(ec_filesys_t *filesys, ec_filesys_res_t *res);
int ec_filesys_del_resource(ec_filesys_t *filesys, const char *uri);
ec_filesys_rep_t *ec_filesys_get_rep(ec_filesys_t *filesys,
        const char *uri, ec_mt_t media_type, const ev_uint8_t *etag);
ec_filesys_rep_t *ec_filesys_get_suitable_rep(ec_filesys_t *filesys,
        const char *uri, ec_mt_t *mta, size_t mta_sz, const ev_uint8_t *etag);


/* Resource. */
ec_filesys_res_t *ec_filesys_new_resource(const char *uri, ev_uint32_t max_age);
void ec_filesys_free_resource(ec_filesys_res_t *res);

/* Resource representation. */
int ec_filesys_add_rep(ec_filesys_res_t *res, const ev_uint8_t *data,
        size_t data_sz, ec_mt_t media_type, ev_uint8_t etag[EC_ETAG_SZ]);

#endif  /* !_EC_FS_H_ */
