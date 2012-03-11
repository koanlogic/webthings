#ifndef _PUBAPI_H_
#define _PUBAPI_H_

#include <u/libu.h>
#include "svc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*svc_cb_t)(svc_t *, void *);

struct pubapi_s;
typedef struct pubapi_s pubapi_t;

int pubapi_connect(u_config_t *c, pubapi_t **ppa);
int pubapi_close(pubapi_t *pa);

/* last change timestamp of the service database (poll on this) */
int pubapi_last_update(pubapi_t *pa, time_t *ptimestamp);

/* returns all services (svc_t*) */
int pubapi_fetch_services(pubapi_t *pa, svc_cb_t fun, void *arg);

/* returns all services having the given attribute matching a substring */
int pubapi_fetch_services_by_attr(pubapi_t *pa, svc_cb_t fun, void *arg,
        const char *attr_name, const char *substr);

#ifdef __cplusplus
}
#endif

#endif  /* !_PUBAPI_H_ */
