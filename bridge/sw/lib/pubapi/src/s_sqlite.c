#include <u/libu.h>
#include <svc.h>
#include "sqlite3.h"
#include "storage_drv.h"

typedef struct qctx_s
{
    int origin_id;
    int path_id;
    svc_t *svc;
    int (*cb_fun)(svc_t *, void *);
    void *cb_arg;
} qctx_t;

static void s_sqlite_svc_ready(qctx_t *qc)
{
    if(qc->svc == NULL)
        return;

    qc->cb_fun(qc->svc, qc->cb_arg);
}

static int s_origins_cb(void *arg, int ncols, char **res, char **colnames)
{
    qctx_t *qc = (qctx_t*)arg;
    int i, origin_id, path_id, attr_id, port;
    const char *schema, *ip, *path, *attr_name, *attr_val;

    u_unused_args(ncols, colnames);

    i = 0;
    origin_id = atoi(res[i++]);
    path_id = atoi(res[i++]);
    attr_id = atoi(res[i++]);
    schema = res[i++];
    ip = res[i++];
    port = res[i] ? atoi(res[i]) : 0; i++;
    path = res[i++];
    attr_name = res[i++];
    attr_val = res[i++];

    if(attr_val == NULL)
        attr_val = "";

    if(qc->origin_id == origin_id && qc->path_id == path_id)
    {
        dbg_err_if(svc_set_attr(qc->svc, attr_name, attr_val));
        return 0;
    }

    if(qc->svc)
    {
        s_sqlite_svc_ready(qc);
        svc_free(qc->svc); 
        qc->svc = NULL;
    }

    dbg_err_if(svc_create(&qc->svc));

    dbg_err_if(svc_set_uri(qc->svc, schema, ip, port, path));

    dbg_err_if(svc_set_attr(qc->svc, attr_name, attr_val));

    qc->origin_id = origin_id;
    qc->path_id = path_id;

    return 0; 
err:
    return ~0; /* stop getting results */
}


static int qctx_free(qctx_t *qc)
{
    dbg_err_if(qc == NULL);

    if(qc->svc)
        svc_free(qc->svc);

    u_free(qc);

    return 0;
err:
    return ~0;
}

static int qctx_create(qctx_t **pqc)
{
    qctx_t *qc = NULL;

    qc = u_zalloc(sizeof(qctx_t));
    dbg_err_if(qc == NULL);

    *pqc = qc;

    return 0;
err:
    return ~0;
}

static int s_sqlite3_fetch_services_by_attr(void *db, svc_cb_t fun, void *arg,
        const char *name, const char *sub_str)
{
    sqlite3 *sqlite = (sqlite3*)db;
    qctx_t *qc = NULL;
    char *hquery = NULL;
    const char *q, *all;

    all = "select o.id,p.id,a.id,o.schema,o.ip,o.port,p.path,a.name,a.value "
        "from attribute a left join path p on a.path_id=p.id left "
        "join origin o on p.origin_id=o.id";

    dbg_err_if(qctx_create(&qc));

    qc->cb_fun = fun;
    qc->cb_arg = arg;

    if(name && sub_str)
    {
        hquery = sqlite3_mprintf(
            "%s where p.id in (select path_id from attribute where name='%q' and "
            "value like '%%%q%%') order by o.id,p.id,a.id", all, name, sub_str);
        dbg_err_if(hquery == NULL);

        q = hquery;
    } else if(name) {
        hquery = sqlite3_mprintf(
            "%s where p.id in (select path_id from attribute where name='%q') "
            "order by o.id,p.id,a.id", all, name);
        dbg_err_if(hquery == NULL);

        q = hquery;
    } else {
        hquery = sqlite3_mprintf("%s order by o.id,p.id,a.id", all );
        dbg_err_if(hquery == NULL);

        q = hquery;
    }

    dbg_err_if(sqlite3_exec(sqlite, q, s_origins_cb, qc, NULL));

    s_sqlite_svc_ready(qc);

    if(hquery)
        sqlite3_free(hquery);

    qctx_free(qc);

    return 0;
err:
    if(hquery)
        sqlite3_free(hquery);
    if(qc)
        qctx_free(qc);
    return ~0;
}

static int s_sqlite3_fetch_services(void *db, svc_cb_t fun, void *arg)
{
    return s_sqlite3_fetch_services_by_attr(db, fun, arg, NULL, NULL);
}

static int s_meta_cb(void *arg, int ncols, char **res, char **colnames)
{
    char **pvalue = (char**)arg;

    u_unused_args(ncols, colnames);

    if(res[0] == NULL)
    {
        *pvalue = NULL;
        return 0;
    }

    *pvalue = u_strdup(res[0]);
    dbg_err_if(*pvalue == NULL);

    return 0;
err:
    return ~0;
}

static int s_sqlite3_meta_get(void *db, const char *name, char **pvalue)
{
    sqlite3 *sqlite = (sqlite3*)db;
    char *q, *value = NULL;

    q = sqlite3_mprintf("select value from meta where name='%q' limit 1", name);
    dbg_err_if(q == NULL);

    dbg_err_if(sqlite3_exec(sqlite, q, s_meta_cb, &value, NULL));

    sqlite3_free(q);

    *pvalue = value;

    return 0;
err:
    if(q)
        sqlite3_free(q);
    return ~0;

}

static int s_sqlite3_close(void *db)
{
    sqlite3 *sqlite = (sqlite3*)db;
    dbg_err_if(sqlite == NULL);

    dbg_err_if(sqlite3_close(sqlite));

    return 0;
err:
    return ~0;
}

static int s_sqlite3_open(const char *fqn, sqlite3 **psqlite)
{
    sqlite3 *sqlite = NULL;

    dbg_err_if(sqlite3_open(fqn, &sqlite));                   
    
    *psqlite = sqlite;

    return 0;
err:
    if(sqlite)
    {
        u_crit("%s", sqlite3_errmsg(sqlite));
        s_sqlite3_close(sqlite);
    }
    return ~0;
}

static int s_sqlite3_connect(u_config_t *c, void **psqlite)
{
    sqlite3 *sqlite = NULL;
    const char *file;

    file = u_config_get_subkey_value(c, "file");
    crit_err_ifm(file == NULL, "sqlite3 filename not set");

    dbg_err_if(s_sqlite3_open(file, &sqlite));

    *psqlite = sqlite;

    return 0;
err:
    return ~0;
}

struct storage_drv drv_sqlite3 = 
{
    .meta_get = s_sqlite3_meta_get,
    .fetch_services_by_attr = s_sqlite3_fetch_services_by_attr,
    .fetch_services = s_sqlite3_fetch_services,
    .connect = s_sqlite3_connect,
    .close = s_sqlite3_close,
};


