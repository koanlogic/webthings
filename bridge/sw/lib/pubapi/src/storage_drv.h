#ifndef _STORAGE_DRV_H_
#define _STORAGE_DRV_H_
#include <u/libu.h>
#include <pubapi.h>

#ifdef __cplusplus
extern "C" {
#endif

struct storage_drv
{
    int (*meta_get)(void *db, const char *name, char **pvalue);
    int (*fetch_services_by_attr)(void *db, svc_cb_t fun, void *arg, 
            const char *name, const char *sub_str);
    int (*fetch_services)(void *db, svc_cb_t fun, void *arg);
    int (*connect)(u_config_t *c, void **pdb);
    int (*close)(void *db);
};

extern struct storage_drv drv_sqlite3;

#ifdef __cplusplus
}
#endif

#endif

