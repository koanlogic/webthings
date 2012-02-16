#ifndef _EC_FS_H_
#define _EC_FS_H_

#include <event2/util.h>
#include <u/libu.h>

#include "evcoap_enums.h"
#include "evcoap_resource.h"
 
/* The filesys is just a wrapper around libu's hmap. */
typedef struct ec_filesys_s { u_hmap_t *map; } ec_filesys_t;

/* File system (basically: you add resources and get representations back.) */
ec_filesys_t *ec_filesys_create(void);
void ec_filesys_destroy(ec_filesys_t *fs);
int ec_filesys_put_resource(ec_filesys_t *filesys, ec_res_t *res);
int ec_filesys_del_resource(ec_filesys_t *filesys, const char *uri);
ec_rep_t *ec_filesys_get_rep(ec_filesys_t *filesys, const char *uri, 
        ec_mt_t media_type, const uint8_t *etag);
ec_rep_t *ec_filesys_get_suitable_rep(ec_filesys_t *fs, const char *uri,
        ec_mt_t *mta, size_t mta_sz, const uint8_t *etag);

#endif  /* !_EC_FS_H_ */
