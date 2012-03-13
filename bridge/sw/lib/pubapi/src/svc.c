#include <u/libu.h>
#include <svc.h>

struct svc_s
{
    u_uri_t *uri;
    u_hmap_t *attrs;
};

int svc_set_origin(svc_t *svc, const char *schema, const char *ip, int port)
{
    char buf[32];

    dbg_err_if(svc == NULL);
    dbg_err_if(schema == NULL);
    dbg_err_if(ip == NULL);

    u_uri_set_scheme(svc->uri, schema);

    u_uri_set_host(svc->uri, ip);

    if(port)
    {
        dbg_err_if(u_snprintf(buf, sizeof(buf), "%d", port));
        u_uri_set_port(svc->uri, buf);
    } 

    return 0;
err:
    return ~0;
}

int svc_set_uri(svc_t *svc, const char *schema, const char *ip, int port,
        const char *path)
{
    dbg_err_if(svc == NULL);
    dbg_err_if(schema == NULL);
    dbg_err_if(ip == NULL);

    dbg_err_if(svc_set_origin(svc, schema, ip, port));

    u_uri_set_path(svc->uri, path);

    return 0;
err:
    return ~0;
}

int svc_set_attr(svc_t *svc, const char *name, const char *val)
{
    dbg_err_if(svc == NULL);
    dbg_err_if(name == NULL);
    dbg_err_if(val == NULL);

    dbg_err_if(u_hmap_easy_put(svc->attrs, name, val));

    return 0;
err:
    return ~0;
}

int svc_uri(svc_t *svc, u_uri_t **puri)
{
    dbg_err_if(svc == NULL);

    dbg_err_if(svc->uri == NULL);

    *puri = svc->uri;

    return 0;
err:
    return ~0;
}

int svc_attrs(svc_t *svc, u_hmap_t **pattrs)
{
    dbg_err_if(svc == NULL);

    dbg_err_if(svc->attrs == NULL);

    *pattrs = svc->attrs;

    return 0;
err:
    return ~0;
}

int svc_attr(svc_t *svc, const char *name, const char **pval)
{
    u_hmap_o_t *o;

    dbg_err_if(u_hmap_get(svc->attrs, name, &o));

    *pval = (const char*)u_hmap_o_get_val(o);

    return 0;
err:
    return ~0;
}

int svc_free(svc_t *svc)
{
    dbg_err_if(svc == NULL);

    if(svc->uri)
        u_uri_free(svc->uri);

    if(svc->attrs)
        u_hmap_free(svc->attrs);

    u_free(svc);

    return 0;
err:
    return ~0;
}

int svc_create(svc_t **psvc)
{
    svc_t *svc = NULL;
    u_hmap_opts_t *opts = NULL;

    svc = u_zalloc(sizeof(svc_t));
    dbg_err_if(svc == NULL);

    dbg_err_if(u_uri_new(0, &svc->uri));

    dbg_err_if(u_hmap_opts_new (&opts));
    dbg_err_if(u_hmap_opts_set_val_type(opts, U_HMAP_OPTS_DATATYPE_STRING));

    dbg_err_if(u_hmap_easy_new(opts, &svc->attrs));

    u_hmap_opts_free(opts); opts = NULL;

    *psvc = svc;

    return 0;
err:
    svc_free(svc);
    return ~0;
}

