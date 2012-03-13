#include <u/libu.h>
#include <event2/util.h> 

#include "evcoap_resource.h"

static bool ec_mt_matches(ec_mt_t mt, ec_mt_t *mta, size_t mta_sz);

ec_res_t *ec_resource_new(const char *uri, ec_method_mask_t methods, 
        uint32_t max_age)
{
    ec_res_t *res = NULL;

    dbg_return_if (uri == NULL, NULL);
    dbg_return_if (!(EC_IS_METHOD_MASK(methods)), NULL);

    dbg_err_sif ((res = u_zalloc(sizeof *res)) == NULL);
    dbg_err_if (u_strlcpy(res->uri, uri, sizeof res->uri));
    res->methods = methods;
    res->max_age = max_age ? max_age : EC_COAP_DEFAULT_MAX_AGE;
    TAILQ_INIT(&res->reps);
    (void) ec_res_attrs_init(res);

    return res;
err:
    if (res)
        ec_resource_free(res);
    return NULL;
}

void ec_resource_free(ec_res_t *res)
{
    if (res)
    {
        ec_rep_t *rep;

        while ((rep = TAILQ_FIRST(&res->reps)) != NULL)
        {
            TAILQ_REMOVE(&res->reps, rep, next);
            ec_rep_free(rep);
        }
        u_free(res);
    }
    return;
}

int ec_resource_add_rep(ec_res_t *res, const uint8_t *data, size_t data_sz, 
        ec_mt_t media_type, uint8_t etag[EC_ETAG_SZ])
{
    ec_rep_t *rep = NULL;

    dbg_return_if (res == NULL, -1);

    /* Create new representation. */
    dbg_err_if ((rep = ec_rep_new(res, data, data_sz, media_type)) == NULL);

    /* Return the ETag to the caller. */
    if (etag)
        memcpy(etag, rep->etag, EC_ETAG_SZ);

    /* Stick the created representation to its parent resource. */
    TAILQ_INSERT_TAIL(&res->reps, rep, next);

    return 0;
err:
    if (rep)
        ec_rep_free(rep);
    return -1;
}

ec_rep_t *ec_rep_new(ec_res_t *res, const uint8_t *data, size_t data_sz, 
        ec_mt_t media_type)
{
    ec_rep_t *rep = NULL;

    dbg_err_sif ((rep = u_zalloc(sizeof *rep)) == NULL);
    rep->res = res;

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
        ec_rep_free(rep); 
    return NULL;
}

ec_res_t *ec_rep_get_res(ec_rep_t *rep)
{
    dbg_return_if (rep == NULL, NULL);

    return rep->res;
}

/* 'etag' is optional (set it to NULL if you don't want it to be used as
 * lookup parameter.)
 * 'media_type' is optional (set it to EC_MT_ANY if you don't care about
 *  a specific representation.) */
ec_rep_t *ec_resource_get_rep(ec_res_t *res, const char *uri, 
        ec_mt_t media_type, const uint8_t *etag)
{
    ec_mt_t mta[1] = { [0] = media_type };
    size_t mta_sz = 1;

    if (media_type == EC_MT_ANY)
       mta_sz = 0;  /* See ec_mt_matches(). */

    return ec_resource_get_suitable_rep(res, uri, mta, mta_sz, etag);
}

ec_rep_t *ec_resource_get_suitable_rep(ec_res_t *res, const char *uri, 
        ec_mt_t *mta, size_t mta_sz, const uint8_t *etag)
{
    bool mt_match, et_match;
    ec_rep_t *rep = NULL;

    dbg_return_if (res == NULL, NULL);
    dbg_return_if (uri == NULL || *uri == '\0', NULL);

    /* Try to get a matching representation. */
    TAILQ_FOREACH (rep, &res->reps, next)
    {
        mt_match = (ec_mt_matches(rep->media_type, mta, mta_sz))
            ? true : false;

        et_match = (etag == NULL || !memcmp(rep->etag, etag, sizeof rep->etag))
            ? true : false;

        if (mt_match && et_match)
            return rep;
    }

    /* Fall through. */
err:
    return NULL;
}

static bool ec_mt_matches(ec_mt_t mt, ec_mt_t *mta, size_t mta_sz)
{
    size_t i;

    /* An empty array is acceptable, and means EC_MT_ANY. */
    if (mta_sz == 0)
        return true;

    for (i = 0; i < mta_sz; ++i)
    {
        if (mta[i] == mt)
            return true;
    }

    return false;
}

int ec_resource_check_method(ec_res_t *res, ec_method_t method)
{
    ec_method_mask_t mmask;

    dbg_return_if (res == NULL, -1);
    dbg_return_if (!EC_IS_METHOD(method), -1);

    mmask = ec_method_to_mask(method);

    return ec_method_to_mask(res->methods & mmask) ? 0 : -1;
}

void ec_rep_free(ec_rep_t *rep)
{
    if (rep)
    {
        if (rep->data)
           u_free(rep->data);
        u_free(rep);
    }
}

char *ec_res_link_format_str(const ec_res_t *res, const char *origin,
        const char *query, char s[EC_LINK_FMT_MAX])
{
    size_t sz;
    ec_mt_t mt;
    ec_rep_t *rep;
    bool exportable, observable, has_sz = true, has_mt = true;
    char interface[EC_RES_ATTR_MAX], res_type[EC_RES_ATTR_MAX];

    dbg_return_if (res == NULL, NULL);
    dbg_return_if (s == NULL, NULL);

    dbg_err_if (ec_res_attrs_get_if(res, interface));
    dbg_err_if (ec_res_attrs_get_rt(res, res_type));
    dbg_err_if (ec_res_attrs_get_obs(res, &observable));
    dbg_err_if (ec_res_attrs_get_exp(res, &exportable));

    dbg_err_if ((rep = TAILQ_FIRST(&res->reps)) == NULL);

    sz = rep->data_sz, mt = rep->media_type;

    TAILQ_FOREACH (rep, &res->reps, next)
    {
        if (rep->data_sz != sz)
            has_sz = false;

        if (rep->media_type != mt)
            has_mt = false;
    }

    /* TODO filter using query string. */
    /* TODO filter using the origin string. */

    dbg_err_if (u_strlcat(s, "<", EC_LINK_FMT_MAX));
    dbg_err_if (u_strlcat(s, res->uri, EC_LINK_FMT_MAX));
    dbg_err_if (u_strlcat(s, ">", EC_LINK_FMT_MAX));

    if (res_type[0] != '\0')
    {
        dbg_err_if (u_strlcat(s, ";", EC_LINK_FMT_MAX));
        dbg_err_if (u_strlcat(s, "rt=", EC_LINK_FMT_MAX));
        dbg_err_if (u_strlcat(s, res_type, EC_LINK_FMT_MAX));
    }

    if (interface[0] != '\0')
    {
        dbg_err_if (u_strlcat(s, ";", EC_LINK_FMT_MAX));
        dbg_err_if (u_strlcat(s, "if=", EC_LINK_FMT_MAX));
        dbg_err_if (u_strlcat(s, interface, EC_LINK_FMT_MAX));
    }

    if (has_sz)
    {
        char sz_val[16] = { '\0' };

        dbg_err_if (u_snprintf(sz_val, sizeof sz_val, "%zu", sz));
        dbg_err_if (u_strlcat(s, ";", EC_LINK_FMT_MAX));
        dbg_err_if (u_strlcat(s, "sz=", EC_LINK_FMT_MAX));
        dbg_err_if (u_strlcat(s, sz_val, EC_LINK_FMT_MAX));
    }

    if (has_mt)
    {
        char mt_val[4] = { '\0' };

        dbg_err_if (u_snprintf(mt_val, sizeof mt_val, "%u", (unsigned int) mt));
        dbg_err_if (u_strlcat(s, ";", EC_LINK_FMT_MAX));
        dbg_err_if (u_strlcat(s, "ct=", EC_LINK_FMT_MAX));
        dbg_err_if (u_strlcat(s, mt_val, EC_LINK_FMT_MAX));
    }

    if (observable) 
    {
        dbg_err_if (u_strlcat(s, ";", EC_LINK_FMT_MAX));
        dbg_err_if (u_strlcat(s, "obs", EC_LINK_FMT_MAX));
    }

    if (exportable) 
    {
        dbg_err_if (u_strlcat(s, ";", EC_LINK_FMT_MAX));
        dbg_err_if (u_strlcat(s, "exp", EC_LINK_FMT_MAX));
    }

    return s;
err:
    return NULL;
}

int ec_res_attrs_init(ec_res_t *res)
{
    dbg_return_if (res == NULL, -1);

    memset(&res->attrs, 0, sizeof res->attrs);

    return 0;
}

int ec_res_attrs_set_obs(ec_res_t *res, bool observable)
{
    dbg_return_if (res == NULL, -1);

    res->attrs.obs = observable;

    return 0;
}

int ec_res_attrs_set_exp(ec_res_t *res, bool exportable)
{
    dbg_return_if (res == NULL, -1);

    res->attrs.exp = exportable;

    return 0;
}

int ec_res_attrs_set_if(ec_res_t *res, const char *interface)
{
    dbg_return_if (res == NULL, -1);
    dbg_return_if (interface == NULL, -1);

    dbg_return_if (u_strlcpy(res->attrs.interface, interface, 
                sizeof res->attrs.interface), -1);
    return 0;
}

int ec_res_attrs_set_rt(ec_res_t *res, const char *res_type)
{
    dbg_return_if (res == NULL, -1);
    dbg_return_if (res_type == NULL, -1);

    dbg_return_if (u_strlcpy(res->attrs.res_type, res_type, 
                sizeof res->attrs.res_type), -1);
    return -1;
}

int ec_res_attrs_get_obs(const ec_res_t *res, bool *observable)
{
    dbg_return_if (res == NULL, -1);
    dbg_return_if (observable == NULL, -1);

    *observable = res->attrs.obs;

    return 0;
}

int ec_res_attrs_get_exp(const ec_res_t *res, bool *exportable)
{
    dbg_return_if (res == NULL, -1);
    dbg_return_if (exportable == NULL, -1);

    *exportable = res->attrs.exp; 

    return 0;
}

int ec_res_attrs_get_if(const ec_res_t *res, char interface[EC_RES_ATTR_MAX])
{
    dbg_return_if (res == NULL, -1);
    dbg_return_if (interface == NULL, -1);

    dbg_return_if (u_strlcpy(interface, res->attrs.interface, 
                EC_RES_ATTR_MAX), -1);

    return 0;
}

int ec_res_attrs_get_rt(const ec_res_t *res, char res_type[EC_RES_ATTR_MAX])
{
    dbg_return_if (res == NULL, -1);
    dbg_return_if (res_type == NULL, -1);

    dbg_return_if (u_strlcpy(res_type, res->attrs.res_type, 
                EC_RES_ATTR_MAX), -1);

    return 0;
}


