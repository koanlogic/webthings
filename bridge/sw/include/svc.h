#ifndef _SVC_H_
#define _SVC_H_

#include <u/libu.h>

#ifdef __cplusplus
extern "C" {
#endif

struct svc_s;
typedef struct svc_s svc_t;

int svc_create(svc_t **psvc);
int svc_free(svc_t *svc);

/* full uri of the service schema://ip[:port]/path */
int svc_uri(svc_t *svc, u_uri_t **puri);

/* list of name/value attributes */
int svc_attrs(svc_t *svc, u_hmap_t **pattrs);

/* get the value of a single attribute (*pval may be NULL) */
int svc_attr(svc_t *svc, const char *name, const char **pval);

/* set the url from its components */
int svc_set_origin(svc_t *svc, const char *schema, const char *ip, int port);
int svc_set_uri(svc_t *svc, const char *schema, const char *ip, int port, 
        const char *path);

/* set a single attribute */
int svc_set_attr(svc_t *svc, const char *name, const char *val);

#ifdef __cplusplus
}
#endif

#endif
