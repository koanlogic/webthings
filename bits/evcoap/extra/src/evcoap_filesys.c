#include "evcoap_filesys.h"

static void __free_resource(void *arg);
static void ec_filesys_free_representation(ec_filesys_rep_t *rep);
static ec_filesys_rep_t *ec_filesys_new_representation(const ev_uint8_t *data,
        size_t data_sz, ec_mt_t media_type);

ec_filesys_t *ec_filesys_create(void)
{
    ec_filesys_t *fs = NULL;
    u_hmap_t *hmap = NULL;

    u_hmap_opts_t *opts = NULL;

    dbg_err_sif ((fs = u_zalloc(sizeof *fs)) == NULL);

    dbg_err_if (u_hmap_opts_new(&opts));
    dbg_err_if (u_hmap_opts_set_val_type(opts, U_HMAP_OPTS_DATATYPE_POINTER));
    dbg_err_if (u_hmap_opts_set_val_freefunc(opts, __free_resource));

    /* TODO check overwrite with stewy */
 
    dbg_err_if (u_hmap_easy_new(opts, &hmap));

    u_hmap_opts_free(opts), opts = NULL;

    fs->map = hmap, hmap = NULL;

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

int ec_filesys_add_resource(ec_filesys_t *filesys, ec_filesys_res_t *res)
{
    dbg_return_if (filesys == NULL, -1);
    dbg_return_if (res == NULL, -1);
    dbg_return_if (res->uri[0] == '\0', -1);

    dbg_return_if (u_hmap_easy_put(filesys->map, res->uri, res), -1);

    return 0;
}

int ec_filesys_del_resource(ec_filesys_t *filesys, const char *uri)
{
    dbg_return_if (filesys == NULL, -1);
    dbg_return_if (uri == NULL, -1);

    dbg_return_if (u_hmap_easy_del(filesys->map, uri), -1);

    return -1;
}

ec_filesys_res_t *ec_filesys_new_resource(const char *uri, ev_uint32_t max_age)
{
    ec_filesys_res_t *res = NULL;

    dbg_err_sif ((res = u_zalloc(sizeof *res)) == NULL);
    dbg_err_if (u_strlcpy(res->uri, uri, sizeof res->uri));
    res->max_age = max_age ? max_age : 60;
    TAILQ_INIT(&res->reps);

    return res;
err:
    if (res)
        ec_filesys_free_resource(res);
    return NULL;
}

void ec_filesys_free_resource(ec_filesys_res_t *res)
{
    if (res)
    {
        ec_filesys_rep_t *rep;

        while ((rep = TAILQ_FIRST(&res->reps)) != NULL)
        {
            TAILQ_REMOVE(&res->reps, rep, next);
            ec_filesys_free_representation(rep);
        }

        u_free(res);
    }

    return;
}

int ec_filesys_add_representation(ec_filesys_res_t *res, const ev_uint8_t *data,
        size_t data_sz, ec_mt_t media_type)
{
    ec_filesys_rep_t *rep = NULL;

    dbg_return_if (res == NULL, -1);

    /* Create new representation. */
    dbg_err_if ((rep = ec_filesys_new_representation(data, data_sz,
                    media_type)) == NULL);

    /* Stick it to its parent resource. */
    TAILQ_INSERT_TAIL(&res->reps, rep, next);

    return 0;
err:
    if (rep)
        ec_filesys_free_representation(rep);
    return -1;
}

static ec_filesys_rep_t *ec_filesys_new_representation(const ev_uint8_t *data,
        size_t data_sz, ec_mt_t media_type)
{
    ec_filesys_rep_t *rep = NULL;

    dbg_err_sif ((rep = u_zalloc(sizeof *rep)) == NULL);

    if (data && data_sz)
    {
        dbg_err_if ((rep->data = u_memdup(data, data_sz)) == NULL);
        rep->data_sz = data_sz;
    }

    rep->media_type = media_type;

    /* Attach a random etag on registration. */
    evutil_secure_rng_get_bytes(rep->etag, sizeof rep->etag);

    return rep;
err:
    if (rep)
        ec_filesys_free_representation(rep); 
    return NULL;
}

static void ec_filesys_free_representation(ec_filesys_rep_t *rep)
{
    if (rep)
    {
        if (rep->data)
           u_free(rep->data);
        u_free(rep);
    }
}

/* Wrapper to make hmap happy. */
static void __free_resource(void *arg)
{
    ec_filesys_free_resource((ec_filesys_res_t *) arg);
    return;
}

