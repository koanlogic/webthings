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

struct ec_opt_s *ec_opt_new(ec_opt_t sym, size_t l, const ev_uint8_t *v)
{
    size_t vlen;
    struct ec_opt_s *opt = NULL;

    dbg_err_sif ((opt = u_zalloc(sizeof *opt)) == NULL);

    opt->sym = sym;

    switch ((opt->t = ec_opt_sym2type(sym)))
    {
        case EC_OPT_TYPE_INVALID:
            dbg_err("invalid option type");
        case EC_OPT_TYPE_EMPTY:
            return 0;
        default:
            break;
    }

    dbg_err_if ((opt->l = l) > EC_OPT_LEN_MAX);

    /* Make room for the option value. */
    vlen = (opt->t != EC_OPT_TYPE_STRING) ? opt->l : opt->l + 1;
    dbg_err_sif ((opt->v = u_malloc(vlen)) == NULL);
    memcpy(opt->v, v, opt->l);

    /* Be C friendly: NUL-terminate in case it's a string. */
    if (opt->t == EC_OPT_TYPE_STRING)
        opt->v[vlen - 1] = '\0';

    return opt;
err:
    if (opt)
        ec_opt_free(opt);
    return NULL;
}

void ec_opt_free(struct ec_opt_s *o)
{
    if (o)
    {
        u_free(o->v);
        u_free(o);
    }
}

ec_opt_type_t ec_opt_sym2type(ec_opt_t sym)
{
    dbg_return_if (!EC_OPT_SYM_VALID(sym), EC_OPT_TYPE_INVALID);

    return g_opts[sym].t;
}   

int ec_opt_push(struct ec_opts_s *opts, struct ec_opt_s *o)
{
    struct ec_opt_s *tmp;
    
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

int ec_opt_add(struct ec_opts_s *opts, ec_opt_t sym, const ev_uint8_t *v,
        size_t l)
{
    struct ec_opt_s *o = NULL;

    dbg_err_if ((o = ec_opt_new(sym, l, v)) == NULL);
    dbg_err_if (ec_opt_push(opts, o));
    o = NULL;

    return 0;
err:
    if (o)
        ec_opt_free(o);
    return -1;
}

/* 'v' is the complete value, which will be fragmented in one or more option 
 *  * slots if needed. */
int ec_opt_add_raw(struct ec_opts_s *opts, ec_opt_t sym,
        const ev_uint8_t *v,  size_t l)
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
        dbg_err_if (ec_opt_add(opts, sym, v + offset, EC_OPT_LEN_MAX));
    
        /* Shift offset to point next fragment. */
        offset = nseg * EC_OPT_LEN_MAX;
    }
    
    /* Take care of the "remainder" slot (or an empty option.)
     * (TODO check that option is allowed to be zero length?) */
    if (rem || !l)
    {
        dbg_err_if (ec_opt_add(opts, sym, v + offset, !l ? 0 : rem));
    }
    
    return 0;
err:
    return -1;
}

int ec_opt_add_uint(struct ec_opts_s *opts, ec_opt_t sym, ev_uint64_t v)
{
    ev_uint8_t e[8];
    size_t elen = sizeof e;

    dbg_return_if (ec_opt_sym2type(sym) != EC_OPT_TYPE_UINT, -1);
    dbg_return_if (ec_opt_encode_uint(v, e, &elen), -1);

    return ec_opt_add_raw(opts, sym, e, elen);
}

int ec_opt_add_string(struct ec_opts_s *opts, ec_opt_t sym, const char *s)
{
    dbg_return_if (ec_opt_sym2type(sym) != EC_OPT_TYPE_STRING, -1);

    return ec_opt_add_raw(opts, sym, (ev_uint8_t *) s, strlen(s));
}

int ec_opt_add_opaque(struct ec_opts_s *opts, ec_opt_t sym, const ev_uint8_t *v,
        size_t l)
{
    dbg_return_if (ec_opt_sym2type(sym) != EC_OPT_TYPE_OPAQUE, -1);

    return ec_opt_add_raw(opts, sym, v, l);
}

int ec_opt_add_empty(struct ec_opts_s *opts, ec_opt_t sym)
{
    dbg_return_if (ec_opt_sym2type(sym) != EC_OPT_TYPE_EMPTY, -1);

    return ec_opt_add_raw(opts, sym, NULL, 0);
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
    
    /* XXX Assume LE host. */
    /* TODO BE host (nop). */
    for (j = 0; j <= i; ++j)
        e[j] = (ui >> (8 * j)) & 0xff;
    
    *elen = i + 1;
    
    return 0;
err:
    return -1;
}



