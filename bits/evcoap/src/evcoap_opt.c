#include <u/libu.h>
#include "evcoap_opt.h"

static struct opt_rec {
    size_t n;               /* Option number. */
    const char *s;          /* Option human readable name. */
    ec_opt_type_t t;
} g_opts[] = {
    { 0,  "Invalid",        EC_OPT_TYPE_INVALID },
    { 1,  "Content-Type",   EC_OPT_TYPE_UINT },
    { 2,  "Max-Age",        EC_OPT_TYPE_UINT },
    { 3,  "Proxy-URI",      EC_OPT_TYPE_STRING },
    { 4,  "ETag",           EC_OPT_TYPE_OPAQUE },
    { 5,  "URI-Host",       EC_OPT_TYPE_STRING },
    { 6,  "Location-Path",  EC_OPT_TYPE_STRING },
    { 7,  "URI-Port",       EC_OPT_TYPE_UINT },
    { 8,  "Location-Query", EC_OPT_TYPE_STRING },
    { 9,  "URI-Path",       EC_OPT_TYPE_STRING },
    { 10, "Observe",        EC_OPT_TYPE_UINT },
    { 11, "Token",          EC_OPT_TYPE_OPAQUE },
    { 12, "Accept",         EC_OPT_TYPE_UINT },
    { 13, "If-Match",       EC_OPT_TYPE_OPAQUE },
    { 14, "Max-OFE",        EC_OPT_TYPE_UINT },
    { 15, "URI-Query",      EC_OPT_TYPE_STRING },
    { 21, "If-None-Match",  EC_OPT_TYPE_EMPTY }
};
#define EC_OPTS_MAX (sizeof g_opts / sizeof(struct opt_rec))

ec_opt_t *ec_opt_new(ec_opt_sym_t sym, size_t l, const ev_uint8_t *v)
{
    size_t vlen;
    ec_opt_t *o = NULL;

    dbg_err_sif ((o = u_zalloc(sizeof *o)) == NULL);

    o->sym = sym;

    switch ((o->t = ec_opt_sym2type(sym)))
    {
        case EC_OPT_TYPE_INVALID:
            dbg_err("invalid option type");
        case EC_OPT_TYPE_EMPTY:
            return 0;
        case EC_OPT_TYPE_UINT:
        case EC_OPT_TYPE_STRING:
        case EC_OPT_TYPE_OPAQUE:
            break;
        default:
            dbg_err("unknown option type");
    }

    dbg_err_if ((o->l = l) > EC_OPT_LEN_MAX);

    /* Make room for the option value. */
    vlen = (o->t != EC_OPT_TYPE_STRING) ? o->l : o->l + 1;
    dbg_err_sif ((o->v = u_malloc(vlen)) == NULL);
    memcpy(o->v, v, o->l);

    /* Be C friendly: NUL-terminate in case it's a string. */
    if (o->t == EC_OPT_TYPE_STRING)
        o->v[vlen - 1] = '\0';

    return o;
err:
    if (o)
        ec_opt_free(o);
    return NULL;
}

void ec_opt_free(ec_opt_t *o)
{
    if (o)
    {
        u_free(o->v);
        u_free(o);
    }
}

ec_opt_type_t ec_opt_sym2type(ec_opt_sym_t sym)
{
    dbg_return_if (!EC_OPT_SYM_VALID(sym), EC_OPT_TYPE_INVALID);

    return g_opts[sym].t;
}   

int ec_opts_push(ec_opts_t *opts, ec_opt_t *o)
{
    ec_opt_t *tmp;
    
    dbg_return_if (opts->noptions == EC_PROTO_MAX_OPTIONS, -1);
    
    /* 
     * Ordered (lo[0]..hi[n]) insertion of new elements.
     */
    
    /* Empty. */
    if (TAILQ_EMPTY(&opts->bundle))
    {
        TAILQ_INSERT_TAIL(&opts->bundle, o, next);
        goto end;
    }
    
    /* Not the lowest. */
    TAILQ_FOREACH_REVERSE(tmp, &opts->bundle, ec_opts, next)
    {
        if (o->sym >= tmp->sym)
        {
            TAILQ_INSERT_AFTER(&opts->bundle, tmp, o, next);
            goto end;
        }
    }
    
    /* Lowest. */
    TAILQ_INSERT_HEAD(&opts->bundle, o, next);

    /* Fall through. */
end:
    opts->noptions += 1;
    return 0;
}

int ec_opts_add(ec_opts_t *opts, ec_opt_sym_t sym, const ev_uint8_t *v, 
        size_t l)
{
    ec_opt_t *o = NULL;

    dbg_err_if ((o = ec_opt_new(sym, l, v)) == NULL);
    dbg_err_if (ec_opts_push(opts, o));
    o = NULL;

    return 0;
err:
    if (o)
        ec_opt_free(o);
    return -1;
}

/* 'v' is the complete value, which will be fragmented in one or more option 
 *  * slots if needed. */
int ec_opts_add_raw(ec_opts_t *opts, ec_opt_sym_t sym, const ev_uint8_t *v,  
        size_t l)
{
    size_t nseg, offset = 0,
           full_seg_no = l / EC_OPT_LEN_MAX,
           rem = l % EC_OPT_LEN_MAX,
           to_be_used_opts = (full_seg_no + ((rem || !l) ? 1 : 0));
    
    /* First off, check if we have enough slots available
     * to encode the supplied option. */
    dbg_err_ifm (opts->noptions + to_be_used_opts > EC_PROTO_MAX_OPTIONS,
            "not enough slots available to encode option");
    
    /* Handle option fragmentation. */
    for (nseg = 0; nseg < full_seg_no; nseg++)
    {
        dbg_err_if (ec_opts_add(opts, sym, v + offset, EC_OPT_LEN_MAX));
    
        /* Shift offset to point next fragment. */
        offset = nseg * EC_OPT_LEN_MAX;
    }
    
    /* Take care of the "remainder" slot (or an empty option.)
     * (TODO check that option is allowed to be zero length?) */
    if (rem || !l)
    {
        dbg_err_if (ec_opts_add(opts, sym, v + offset, !l ? 0 : rem));
    }
    
    return 0;
err:
    return -1;
}

int ec_opts_add_uint(ec_opts_t *opts, ec_opt_sym_t sym, ev_uint64_t v)
{
    ev_uint8_t e[8];
    size_t elen = sizeof e;

    dbg_return_if (ec_opt_sym2type(sym) != EC_OPT_TYPE_UINT, -1);
    dbg_return_if (ec_opt_encode_uint(v, e, &elen), -1);

    return ec_opts_add_raw(opts, sym, e, elen);
}

int ec_opts_add_string(ec_opts_t *opts, ec_opt_sym_t sym, const char *s)
{
    dbg_return_if (ec_opt_sym2type(sym) != EC_OPT_TYPE_STRING, -1);

    return ec_opts_add_raw(opts, sym, (const ev_uint8_t *) s, strlen(s));
}

int ec_opts_add_opaque(ec_opts_t *opts, ec_opt_sym_t sym, const ev_uint8_t *v,
        size_t l)
{
    dbg_return_if (ec_opt_sym2type(sym) != EC_OPT_TYPE_OPAQUE, -1);

    return ec_opts_add_raw(opts, sym, v, l);
}

int ec_opts_add_empty(ec_opts_t *opts, ec_opt_sym_t sym)
{
    dbg_return_if (ec_opt_sym2type(sym) != EC_OPT_TYPE_EMPTY, -1);

    return ec_opts_add_raw(opts, sym, NULL, 0);
}

/* 'elen' is value-result argument.  It MUST be initially set to the size
 * of 'e'.  On a successful return it will hold the lenght of the encoded 
 * uint (i.e. # of valid bytes in 'e'.) */
int ec_opt_encode_uint(ev_uint64_t ui, ev_uint8_t *e, size_t *elen)
{
    size_t i, j;
    
    ev_uint64_t ui_bytes[] =
    {
        (1ULL <<  8) - 1,
        (1ULL << 16) - 1,
        (1ULL << 24) - 1,
        (1ULL << 32) - 1,
        (1ULL << 40) - 1,
        (1ULL << 48) - 1,
        (1ULL << 56) - 1,
        UINT64_MAX
    };
    
    /* Pick size. */
    for (i = 0; i < (sizeof ui_bytes / sizeof(ev_uint64_t)); i++)
        if (ui_bytes[i] > ui)
            break;
    
    dbg_err_ifm (*elen < i + 1, "not enough bytes for encoding %llu", ui);
    
#ifdef EC_LITTLE_ENDIAN
    for (j = 0; j <= i; ++j)
        e[j] = (ui >> (8 * j)) & 0xff;
#else
    #error "TODO big endian uint encoder"
#endif  /* EC_LITTLE_ENDIAN */
    
    *elen = i + 1;
    
    return 0;
err:
    return -1;
}

ec_opt_t *ec_opts_get_nth(ec_opts_t *opts, ec_opt_sym_t sym, size_t n)
{
    ec_opt_t *o;

    TAILQ_FOREACH(o, &opts->bundle, next)
    {
        if (o->sym == sym)
        {
            if (n == 0)
                return o;
            --n;
        }
    }

    return NULL;
}

/* Return the first occurrence of 'sym', if available. */
ec_opt_t *ec_opts_get(ec_opts_t *opts, ec_opt_sym_t sym)
{
    return ec_opts_get_nth(opts, sym, 0);
}

const char *ec_opts_get_string(ec_opts_t *opts, ec_opt_sym_t sym)
{

    dbg_return_if (ec_opt_sym2type(sym) != EC_OPT_TYPE_STRING, NULL);

    /* Assume that the setter has NUL-terminated the value buffer. */
    ec_opt_t *o = ec_opts_get(opts, sym);

    return o ? (const char *) o->v : NULL;
}

int ec_opts_get_uint(ec_opts_t *opts, ec_opt_sym_t sym, ev_uint64_t *ui)
{
    dbg_return_if (ec_opt_sym2type(sym) != EC_OPT_TYPE_UINT, -1);

    ec_opt_t *o = ec_opts_get(opts, sym);

    return o ? ec_opt_decode_uint(o->v, o->l, ui) : -1;
}

const char *ec_opts_get_uri_host(ec_opts_t *opts)
{
    return ec_opts_get_string(opts, EC_OPT_URI_HOST);
}

int ec_opts_get_uri_port(ec_opts_t *opts, ev_uint16_t *port)
{
    ev_uint64_t tmp;

    if (ec_opts_get_uint(opts, EC_OPT_URI_PORT, &tmp))
        return -1;

    /* TODO Check overflow */
    *port = (ev_uint16_t) tmp;

    return 0;
}

int ec_opt_decode_uint(const ev_uint8_t *v, size_t l, ev_uint64_t *ui)
{
    size_t i;

    dbg_return_if (l > sizeof(ev_uint64_t), -1);

    *ui = 0;

#ifdef EC_LITTLE_ENDIAN
    for (i = l; i > 0; i--)
        *ui |= (v[i - 1] << (8 * (l - i)));
#else
    #error "TODO big endian uint decoder"
#endif  /* EC_LITTLE_ENDIAN */
 
    return 0;
}

/**
 *  \brief  TODO (user may set a custom content type.)
 */
int ec_opts_add_content_type(ec_opts_t *opts, ev_uint16_t ct)
{
    dbg_return_if (opts == NULL, -1);

    /* Valid range is 0-65535.
     * EC_CT_* enum values are provided for registered content types.
     * 0-2 B length is enforced by 16-bit 'ct'. */

    return ec_opts_add_uint(opts, EC_OPT_CONTENT_TYPE, ct);
}

/**
 *  \brief  TODO
 */
int ec_opts_add_max_age(ec_opts_t *opts, ev_uint32_t ma)
{
    dbg_return_if (opts == NULL, -1);

    /* 0-4 B lenght is enforced by 32-bit 'ma'. */

    return ec_opts_add_uint(opts, EC_OPT_MAX_AGE, ma);
}

/**
 *  \brief  TODO
 */
int ec_opts_add_proxy_uri(ec_opts_t *opts, const char *pu)
{
    dbg_return_if (opts == NULL, -1);
    dbg_return_if (pu == NULL, -1);
    dbg_return_if (!strlen(pu) || strlen(pu) > 270, -1); /* 1-270 B */

    return ec_opts_add_string(opts, EC_OPT_PROXY_URI, pu);
}

/**
 *  \brief  TODO
 */
int ec_opts_add_etag(ec_opts_t *opts, const ev_uint8_t *et, size_t et_len)
{
    dbg_return_if (opts == NULL, -1);
    dbg_return_if (et == NULL, -1);
    dbg_return_if (!et_len || et_len > 8, -1);  /* 1-8 B */

    return ec_opts_add_opaque(opts, EC_OPT_ETAG, et, et_len);
}

/**
 *  \brief  TODO
 */
int ec_opts_add_uri_host(ec_opts_t *opts, const char  *uh)
{
    dbg_return_if (opts == NULL, -1);
    dbg_return_if (uh == NULL, -1);
    dbg_return_if (!strlen(uh) || strlen(uh) > 270, -1);  /* 1-270 B */

    return ec_opts_add_string(opts, EC_OPT_URI_HOST, uh);
}

/**
 *  \brief  TODO
 */
int ec_opts_add_location_path(ec_opts_t *opts, const char *lp)
{
    dbg_return_if (opts == NULL, -1);
    dbg_return_if (lp == NULL, -1);
    dbg_return_if (!strlen(lp) || strlen(lp) > 270, -1);  /* 1-270 B */

    return ec_opts_add_string(opts, EC_OPT_LOCATION_PATH, lp);
}

/**
 *  \brief  TODO
 */
int ec_opts_add_uri_port(ec_opts_t *opts, ev_uint16_t up)
{
    dbg_return_if (opts == NULL, -1);
    /* 0-2 B length is enforced by 16-bit 'up'. */

    return ec_opts_add_uint(opts, EC_OPT_URI_PORT, up);
}

/**
 *  \brief  TODO
 */
int ec_opts_add_location_query(ec_opts_t *opts, const char *lq)
{
    dbg_return_if (opts == NULL, -1);
    dbg_return_if (lq == NULL, -1);
    dbg_return_if (!strlen(lq) || strlen(lq) > 270, -1);  /* 1-270 B */

    return ec_opts_add_string(opts, EC_OPT_LOCATION_QUERY, lq);
}

/**
 *  \brief  TODO
 */
int ec_opts_add_uri_path(ec_opts_t *opts, const char *up)
{
    dbg_return_if (opts == NULL, -1);
    dbg_return_if (up == NULL, -1);
    dbg_return_if (!strlen(up) || strlen(up) > 270, -1);  /* 1-270 B */

    return ec_opts_add_string(opts, EC_OPT_URI_PATH, up);
}

/**
 *  \brief  TODO
 */
int ec_opts_add_token(ec_opts_t *opts, const ev_uint8_t *t, size_t t_len)
{
    dbg_return_if (opts == NULL, -1);
    dbg_return_if (t == NULL, -1);
    dbg_return_if (!t_len || t_len > 8, -1);  /* 1-8 B */

    return ec_opts_add_opaque(opts, EC_OPT_TOKEN, t, t_len);
}

/**
 *  \brief  TODO
 */
int ec_opts_add_accept(ec_opts_t *opts, ev_uint16_t a)
{
    dbg_return_if (opts == NULL, -1);
    /* 0-2 B length is enforced by 16-bit 'a'. */

    return ec_opts_add_uint(opts, EC_OPT_ACCEPT, a);
}

/**
 *  \brief  TODO
 */
int ec_opts_add_if_match(ec_opts_t *opts, const ev_uint8_t *im, 
        size_t im_len)
{
    dbg_return_if (opts == NULL, -1);
    dbg_return_if (im == NULL, -1);
    dbg_return_if (!im_len || im_len > 8, -1);  /* 1-8 B */

    return ec_opts_add_opaque(opts, EC_OPT_IF_MATCH, im, im_len);
}

/**
 *  \brief  TODO
 */
int ec_opts_add_uri_query(ec_opts_t *opts, const char *uq)
{
    dbg_return_if (opts == NULL, -1);
    dbg_return_if (uq == NULL, -1);
    dbg_return_if (!strlen(uq) || strlen(uq) > 270, -1);  /* 1-270 B */

    return ec_opts_add_string(opts, EC_OPT_URI_QUERY, uq);
}

/**
 *  \brief  TODO
 */
int ec_opts_add_if_none_match(ec_opts_t *opts)
{
    dbg_return_if (opts == NULL, -1);

    return ec_opts_add_empty(opts, EC_OPT_IF_NONE_MATCH);
}

/**
 *  \brief  TODO
 */
int ec_opts_add_observe(ec_opts_t *opts, ev_uint16_t o)
{
    dbg_return_if (opts == NULL, -1);
    /* 0-2 B length is enforced by 16-bit 'o'. */

    return ec_opts_add_uint(opts, EC_OPT_OBSERVE, o);
}

/**
 *  \brief  TODO
 */
int ec_opts_add_max_ofe(ec_opts_t *opts, ev_uint32_t mo)
{
    dbg_return_if (opts == NULL, -1);
    /* 0-2 B length is enforced by 32-bit 'mo'. */

    return ec_opts_add_uint(opts, EC_OPT_MAX_OFE, mo);
}
