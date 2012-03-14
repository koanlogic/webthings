#ifndef _EC_FS_H_
#define _EC_FS_H_

#include <event2/util.h>
#include <u/libu.h>

#include "evcoap_enums.h"
#include "evcoap_resource.h"
 
/* The filesys is just a wrapper around libu's hmap. */
typedef struct ec_filesys_s 
{ 
    /* Use relative-ref instead of URI when creating Uri-reference's to
     * be used in link-format. */
    bool rel_refs;
    u_hmap_t *map; 
} ec_filesys_t;

#ifndef EC_WKC_MAX
  #define EC_WKC_MAX    4096
#endif  /* !EC_WKC_MAX */

/* File system (basically: you add resources and get representations back.) */
ec_filesys_t *ec_filesys_create(bool relative_refs);
void ec_filesys_destroy(ec_filesys_t *fs);
int ec_filesys_put_resource(ec_filesys_t *filesys, ec_res_t *res);
int ec_filesys_del_resource(ec_filesys_t *filesys, const char *uri);
ec_rep_t *ec_filesys_get_rep(ec_filesys_t *filesys, const char *uri, 
        ec_mt_t media_type, const uint8_t *etag);
ec_rep_t *ec_filesys_get_suitable_rep(ec_filesys_t *fs, const char *uri,
        ec_mt_t *mta, size_t mta_sz, const uint8_t *etag);
char *ec_filesys_well_known_core(ec_filesys_t *fs, const char *origin,
        const char *query, char wkc[EC_WKC_MAX]);

#endif  /* !_EC_FS_H_ */
