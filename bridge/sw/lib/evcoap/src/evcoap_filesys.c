#include "evcoap_filesys.h"
#include "evcoap_resource.h"

struct ec_wkc_args_s
{
    char *wkc;  /* EC_WKC_MAX */
    const char *origin;
    const char *query;
    bool rel_refs;
};

static void __free_resource(void *arg);
static int __build_wkc(const void *val, const void *arg);

ec_filesys_t *ec_filesys_create(bool relative_refs)
{
    ec_filesys_t *fs = NULL;
    u_hmap_t *hmap = NULL;

    u_hmap_opts_t *opts = NULL;

    dbg_err_sif ((fs = u_zalloc(sizeof *fs)) == NULL);

    dbg_err_if (u_hmap_opts_new(&opts));
    dbg_err_if (u_hmap_opts_set_val_type(opts, U_HMAP_OPTS_DATATYPE_POINTER));
    dbg_err_if (u_hmap_opts_set_val_freefunc(opts, __free_resource));

    /* Let put==update. */
    dbg_err_if (u_hmap_opts_unset_option(opts, U_HMAP_OPTS_NO_OVERWRITE));

    dbg_err_if (u_hmap_easy_new(opts, &hmap));

    u_hmap_opts_free(opts), opts = NULL;

    fs->map = hmap, hmap = NULL;
    fs->rel_refs = relative_refs;

    return fs;
err:
    if (opts)
        u_hmap_opts_free(opts);
    if (hmap)
        u_hmap_free(hmap);
    if (fs)
        ec_filesys_destroy(fs);
    return NULL;
}

void ec_filesys_destroy(ec_filesys_t *fs)
{
    if (fs)
    {
        if (fs->map)
            u_hmap_free(fs->map);
        u_free(fs);
    }
}

/* Add or update the filesys resource 'res'. */
int ec_filesys_put_resource(ec_filesys_t *filesys, ec_res_t *res)
{
    dbg_return_if (filesys == NULL, -1);
    dbg_return_if (res == NULL, -1);
    dbg_return_if (res->uri[0] == '\0', -1);

    /* Since we unset the U_HMAP_OPTS_NO_OVERWRITE option, the following
     * overwrites an existing filesys entry with the same URI. */
    dbg_return_if (u_hmap_easy_put(filesys->map, res->uri, res), -1);

    return 0;
}

int ec_filesys_del_resource(ec_filesys_t *filesys, const char *uri)
{
    dbg_return_if (filesys == NULL, -1);
    dbg_return_if (uri == NULL, -1);

    dbg_return_if (u_hmap_easy_del(filesys->map, uri), -1);

    return 0;
}

/* 'etag' is optional (set it to NULL if you don't want it to be used as
 * lookup parameter.)
 * 'media_type' is optional (set it to EC_MT_ANY if you don't care about
 *  a specific representation.) */
ec_rep_t *ec_filesys_get_rep(ec_filesys_t *fs, const char *uri, 
        ec_mt_t media_type, const ev_uint8_t *etag)
{
    ec_mt_t mta[1] = { [0] = media_type };
    size_t mta_sz = sizeof mta / sizeof(ec_mt_t);

    return ec_filesys_get_suitable_rep(fs, uri, mta, mta_sz, etag);
}

ec_rep_t *ec_filesys_get_suitable_rep(ec_filesys_t *fs, const char *uri,
        ec_mt_t *mta, size_t mta_sz, const uint8_t *etag)
{
    ec_res_t *res;

    dbg_return_if (fs == NULL, NULL);
    dbg_return_if (uri == NULL || *uri == '\0', NULL);

    /* Lookup resource. */
    dbg_return_if ((res = u_hmap_easy_get(fs->map, uri)) == NULL, NULL);

    return ec_resource_get_suitable_rep(res, uri, mta, mta_sz, etag);
}

char *ec_filesys_well_known_core(ec_filesys_t *fs, const char *origin, 
        const char *query, char wkc[EC_WKC_MAX])
{
    struct ec_wkc_args_s args;

    dbg_return_if (fs == NULL, NULL);
    dbg_return_if (wkc == NULL, NULL);
    /* 'query' may be NULL for unfiltered queries. */

    wkc[0] = '\0';

    args.wkc = wkc;
    args.origin = origin;
    args.query = query;
    args.rel_refs = fs->rel_refs;

    dbg_err_if (u_hmap_foreach_arg(fs->map, __build_wkc, &args));

    return wkc;
err:
    return NULL;
}

static int __build_wkc(const void *val, const void *arg)
{
    char lfs[EC_LINK_FMT_MAX] = { '\0' };
    const struct ec_wkc_args_s *a = (const struct ec_wkc_args_s *) arg;
    const ec_res_t *res = (const ec_res_t *) val;

    if (!ec_res_link_format_str(res, a->origin, a->query, a->rel_refs, lfs))
        return 0;   /* Leave a->wkc untouched. */

    if (a->wkc[0] != '\0')
        dbg_err_if (u_strlcat(a->wkc, ",", EC_WKC_MAX));

    dbg_err_if (u_strlcat(a->wkc, lfs, EC_WKC_MAX));

    return 0;
err:
    return -1;
}

/* Wrapper to make hmap happy. */
static void __free_resource(void *arg)
{
    ec_resource_free((ec_res_t *) arg);
    return;
}
