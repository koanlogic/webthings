#ifndef _EC_FS_H_
#define _EC_FS_H_

#include <event2/util.h>
#include <u/libu.h>

#include "evcoap_enums.h"

#define EC_URI_MAX  512

/* The filesys is just a wrapper around libu's hmap. */
typedef struct ec_filesys_s { u_hmap_t *map; } ec_filesys_t;

/* Resource representation with private attributes and data. */
typedef struct ec_filesys_rep_s
{
    ec_mt_t media_type;
    ev_uint8_t etag[4];     /* Automatically computed at insert time. */
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

/* File system. */
ec_filesys_t *ec_filesys_create(void);
void ec_filesys_destroy(ec_filesys_t *fs);
int ec_filesys_add_resource(ec_filesys_t *filesys, ec_filesys_res_t *res);
int ec_filesys_del_resource(ec_filesys_t *filesys, const char *uri);

/* Resource. */
ec_filesys_res_t *ec_filesys_new_resource(const char *uri, ev_uint32_t max_age);
void ec_filesys_free_resource(ec_filesys_res_t *res);

/* Resource representation is not manipulated directly. */
int ec_filesys_add_representation(ec_filesys_res_t *res, const ev_uint8_t *data,
        size_t data_sz, ec_mt_t media_type);

#endif  /* !_EC_FS_H_ */
