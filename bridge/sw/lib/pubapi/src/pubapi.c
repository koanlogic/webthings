#include <u/libu.h>
#include <pubapi.h>
#include <svc.h>
#include "storage_drv.h"

struct pubapi_s
{
    struct storage_drv *drv;
    void *db;
};

int pubapi_last_update(pubapi_t *pa, time_t *ptimestamp)
{
    char *value = NULL;

    dbg_err_if(pa->drv->meta_get(pa->db, "last_update", &value));

    dbg_err_if(value == NULL);

    *ptimestamp = atoi(value);

    u_free(value);

    return 0;
err:
    return ~0;
}

int pubapi_fetch_services(pubapi_t *pa, svc_cb_t fun, void *arg)
{
    dbg_err_if(pa->drv->fetch_services(pa->db, fun, arg));

    return 0;
err:
    return ~0;
}

int pubapi_fetch_services_by_attr(pubapi_t *pa, svc_cb_t fun, void *arg,
        const char *name, const char *sub_str)
{
    dbg_err_if(pa->drv->fetch_services_by_attr(pa->db, fun, arg, name, 
                sub_str));

    return 0;
err:
    return ~0;
}

int pubapi_close(pubapi_t *pa)
{
    dbg_err_if(pa == NULL);

    u_free(pa);

    return 0;
err:
    return ~0;
}

int pubapi_connect(u_config_t *c, pubapi_t **ppa)
{
    pubapi_t *pa = NULL;
    u_config_t *db_conf;
    const char *database, *db_type;

    pa = u_zalloc(sizeof(pubapi_t));
    dbg_err_if(pa == NULL);

    database = u_config_get_subkey_value(c, "database");
    crit_err_ifm(database == NULL, "database config key not found");

    crit_err_ifm(u_config_get_subkey(c, database, &db_conf), 
        "database '%s' config key not found", database);

    db_type = u_config_get_subkey_value(db_conf, "type");
    crit_err_ifm(db_type == NULL, "db type key not found");

    if(strcasecmp(db_type, "sqlite") == 0)
    {
        pa->drv = &drv_sqlite3;
    } else
        crit_err("unknown db type '%s'", db_type);

    u_info("db type: %s", db_type);

    dbg_err_if(pa->drv->connect(db_conf, &pa->db));

    *ppa = pa;

    return 0;
err:
    pubapi_close(pa);
    return ~0;
}

