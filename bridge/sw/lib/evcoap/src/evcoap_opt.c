#include <u/libu.h>
#include <event2/util.h>
#include "evcoap_opt.h"

const char *evutil_format_sockaddr_port(const struct sockaddr *sa, char *out,
        size_t outlen);

static u_uri_t *compose_proxy_uri(ec_opts_t *opts, char uri[U_URI_STRMAX]);
static u_uri_t *compose_uri(ec_opts_t *opts, struct sockaddr_storage *us,
        bool nosec, char uri[U_URI_STRMAX]);

static size_t fenceposts_encsz(size_t cur, size_t last);
static uint8_t *add_fenceposts(ec_opts_t *opts, uint8_t *p, size_t cur, 
        size_t *delta);

/*******************************************************************************
 NOTE: the g_opts array entries *MUST* be kept in sync with the ec_opt_sym_t
       enum in evcoap_opt.h. 
 ******************************************************************************/
static struct opt_rec {
    size_t n;               /* Option number. */
    const char *s;          /* Option human readable name. */
    ec_opt_type_t t;        /* Option implicit type. */
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
    { 15, "URI-Query",      EC_OPT_TYPE_STRING },
    { 17, "Block2",         EC_OPT_TYPE_UINT },
    { 19, "Block1",         EC_OPT_TYPE_UINT },
    { 21, "If-None-Match",  EC_OPT_TYPE_EMPTY }
};
#define EC_OPTS_MAX (sizeof g_opts / sizeof(struct opt_rec))

#define EC_OPT_NUM_IS_FENCEPOST(n)  ((n) && ((n) % 14 == 0))

ec_opt_t *ec_opt_new(ec_opt_sym_t sym, size_t l, const uint8_t *v)
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
            return o;
        case EC_OPT_TYPE_UINT:
        case EC_OPT_TYPE_STRING:
        case EC_OPT_TYPE_OPAQUE:
            break;
        default:
            dbg_err("unknown option type");
    }

    dbg_err_if ((o->l = l) > EC_COAP_OPT_LEN_MAX);

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

size_t ec_opt_sym2num(ec_opt_sym_t sym)
{
    dbg_return_if (!EC_OPT_SYM_VALID(sym), EC_OPT_NONE);

    return g_opts[sym].n;
}

ec_opt_sym_t ec_opt_num2sym(size_t num)
{
    size_t i;

    for (i = 0; i < EC_OPTS_MAX; ++i)
    {
        if (num == g_opts[i].n)
            return (ec_opt_sym_t) i;
    }

    u_dbg("option with number %zu could not be resolved", num);

    return EC_OPT_NONE;
}

const char *ec_opt_sym2str(ec_opt_sym_t sym)
{
    dbg_return_if (!EC_OPT_SYM_VALID(sym), NULL);

    return g_opts[sym].s;
}

void ec_opts_clear(ec_opts_t *opts)
{
    if (opts)
    {
        ec_opt_t *o;

        while ((o = TAILQ_FIRST(&opts->bundle)))
        {
            TAILQ_REMOVE(&opts->bundle, o, next);
            ec_opt_free(o);
        }

        (void) ec_opts_init(opts);
    }
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

int ec_opts_add(ec_opts_t *opts, ec_opt_sym_t sym, const uint8_t *v, 
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
int ec_opts_add_raw(ec_opts_t *opts, ec_opt_sym_t sym, const uint8_t *v,  
        size_t l)
{
    size_t nseg, offset = 0,
           full_seg_no = l / EC_COAP_OPT_LEN_MAX,
           rem = l % EC_COAP_OPT_LEN_MAX,
           to_be_used_opts = (full_seg_no + ((rem || !l) ? 1 : 0));
    
    /* First off, check if we have enough slots available
     * to encode the supplied option. */
    dbg_err_ifm (opts->noptions + to_be_used_opts > EC_PROTO_MAX_OPTIONS,
            "not enough slots available to encode option");
    
    /* Handle option fragmentation. */
    for (nseg = 0; nseg < full_seg_no; )
    {
        dbg_err_if (ec_opts_add(opts, sym, v + offset, EC_COAP_OPT_LEN_MAX));

        /* Shift offset to point next fragment. */
        offset = ++nseg * EC_COAP_OPT_LEN_MAX;
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

int ec_opts_add_uint(ec_opts_t *opts, ec_opt_sym_t sym, uint64_t v)
{
    uint8_t e[8];
    size_t elen = sizeof e;

    dbg_return_if (ec_opt_sym2type(sym) != EC_OPT_TYPE_UINT, -1);
    dbg_return_if (ec_opt_encode_uint(v, e, &elen), -1);

    return ec_opts_add_raw(opts, sym, e, elen);
}

int ec_opts_add_string(ec_opts_t *opts, ec_opt_sym_t sym, const char *s)
{
    dbg_return_if (ec_opt_sym2type(sym) != EC_OPT_TYPE_STRING, -1);

    return ec_opts_add_raw(opts, sym, (const uint8_t *) s, strlen(s));
}

int ec_opts_add_opaque(ec_opts_t *opts, ec_opt_sym_t sym, const uint8_t *v,
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
int ec_opt_encode_uint(uint64_t ui, uint8_t *e, size_t *elen)
{
    size_t i, j;
    
    uint64_t ui_bytes[] =
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
    for (i = 0; i < (sizeof ui_bytes / sizeof(uint64_t)); i++)
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

int ec_opts_count_sym(ec_opts_t *opts, ec_opt_sym_t sym, size_t *n)
{
    ec_opt_t *o;

    dbg_return_if (opts == NULL, -1);
    dbg_return_if (n == NULL, -1);

    TAILQ_FOREACH(o, &opts->bundle, next)
    {
        if (o->sym == sym)
            *n += 1;
    }
     
    return 0;
}

/* 'n' has the same semantics as a C array index (i.e. starts from 0). */
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

int ec_opts_get_uint(ec_opts_t *opts, ec_opt_sym_t sym, uint64_t *ui)
{
    dbg_return_if (ec_opt_sym2type(sym) != EC_OPT_TYPE_UINT, -1);

    ec_opt_t *o = ec_opts_get(opts, sym);

    return o ? ec_opt_decode_uint(o->v, o->l, ui) : -1;
}

const char *ec_opts_get_uri_host(ec_opts_t *opts)
{
    return ec_opts_get_string(opts, EC_OPT_URI_HOST);
}

const char *ec_opts_get_proxy_uri(ec_opts_t *opts, char url[U_URI_STRMAX])
{
    dbg_return_if (compose_proxy_uri(opts, url) == NULL, NULL);
    return url;
}

int ec_opts_get_uri_port(ec_opts_t *opts, uint16_t *port)
{
    uint64_t tmp;

    if (ec_opts_get_uint(opts, EC_OPT_URI_PORT, &tmp))
        return -1;

    dbg_err_ifm (tmp > UINT16_MAX, "Uri-Port encoding overflow");

    *port = (uint16_t) tmp;

    return 0;
err:
    return -1;
}

int ec_opt_decode_uint(const uint8_t *v, size_t l, uint64_t *ui)
{
    size_t i;

    dbg_return_if (l > sizeof(uint64_t), -1);

    *ui = 0;

#ifdef EC_LITTLE_ENDIAN
    for (i = 0; i < l; ++i)
        *ui |= v[i] << (i * 8);
#else
    #error "TODO big endian uint decoder (no-op)"
#endif  /* EC_LITTLE_ENDIAN */
 
    return 0;
}

int ec_opts_add_block1(ec_opts_t *opts, uint32_t num, bool more, 
        uint8_t szx)
{
    return ec_opts_add_block(opts, EC_OPT_BLOCK1, num, more, szx);
}

int ec_opts_add_block2(ec_opts_t *opts, uint32_t num, bool more,
        uint8_t szx)
{
    return ec_opts_add_block(opts, EC_OPT_BLOCK2, num, more, szx);
}

/**
 *  \brief  TODO (user may set a custom content type.)
 */
int ec_opts_add_content_type(ec_opts_t *opts, uint16_t ct)
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
int ec_opts_add_max_age(ec_opts_t *opts, uint32_t ma)
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

    /* "In case the absolute-URI doesn't fit within a single option,
     *  the Proxy-Uri Option MAY be included multiple times in a request 
     *  such that the concatenation of the values results in the single 
     *  absolute-URI".  Remove the 270 limitation on supplied 'pu'. */
    dbg_return_if (!strlen(pu), -1);

    /* Check that "The option value is an absolute-URI" */
    dbg_return_ifm (!u_uri_is_absolute(pu), -1, "'%s' not an absolute-URI", pu);

    return ec_opts_add_string(opts, EC_OPT_PROXY_URI, pu);
}

/**
 *  \brief  TODO
 */
int ec_opts_add_etag(ec_opts_t *opts, const uint8_t *et, size_t et_len)
{
    dbg_return_if (opts == NULL, -1);
    dbg_return_if (et == NULL, -1);
    dbg_return_if (!et_len || et_len > 8, -1);  /* 1-8 B */

    return ec_opts_add_opaque(opts, EC_OPT_ETAG, et, et_len);
}

/**
 *  \brief  TODO
 */
int ec_opts_add_uri_host(ec_opts_t *opts, const char *uh)
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
int ec_opts_add_uri_port(ec_opts_t *opts, uint16_t up)
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
int ec_opts_add_token(ec_opts_t *opts, const uint8_t *t, size_t t_len)
{
    dbg_return_if (opts == NULL, -1);
    dbg_return_if (t == NULL, -1);
    dbg_return_if (!t_len || t_len > 8, -1);  /* 1-8 B */

    return ec_opts_add_opaque(opts, EC_OPT_TOKEN, t, t_len);
}

/**
 *  \brief  TODO
 */
int ec_opts_add_accept(ec_opts_t *opts, uint16_t a)
{
    dbg_return_if (opts == NULL, -1);
    /* 0-2 B length is enforced by 16-bit 'a'. */

    return ec_opts_add_uint(opts, EC_OPT_ACCEPT, a);
}

/**
 *  \brief  TODO
 */
int ec_opts_add_if_match(ec_opts_t *opts, const uint8_t *im, 
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
int ec_opts_add_observe(ec_opts_t *opts, uint16_t o)
{
    dbg_return_if (opts == NULL, -1);
    /* 0-2 B length is enforced by 16-bit 'o'. */

    return ec_opts_add_uint(opts, EC_OPT_OBSERVE, o);
}

int ec_opts_encode(ec_opts_t *opts)
{
    ec_opt_t *o;
    size_t cur, last = 0, delta, left, elen;
    uint8_t *p;

    dbg_return_if (opts == NULL, -1);

    p = opts->enc;
    left = opts->enc_sz = sizeof opts->enc;

    /* Assume options are already ordered from lowest to highest. */
    TAILQ_FOREACH(o, &opts->bundle, next)
    {
        /* Pop next option and process it. */
        dbg_err_if ((cur = ec_opt_sym2num(o->sym)) == EC_OPT_NONE);

        /* Compute how much space we're going to consume, so that we don't
         * have to check at each encode step.
         * XXX Take care of possible fenceposts. */
        elen = ((o->l > 14) ? 2 : 1) + o->l + fenceposts_encsz(cur, last);

        dbg_err_ifm (elen > left,
                "Not enough space (%zu vs %zu) to encode %s",
                elen, left, ec_opt_sym2str(o->sym));

        /* Delta encode the option number. */
        if ((delta = cur - last) > 14)
            dbg_err_if (!(p = add_fenceposts(opts, p, cur, &delta)));

        /* Encode length. */
        if (o->l > 14)
        {
            *p++ = (delta << 4) | 0x0f;
            *p++ = o->l - 15;
        }
        else
            *p++ = (delta << 4) | (o->l & 0x0f);

        /* Put value. */
        if (o->v)
        {
            memcpy(p, o->v, o->l);
            p += o->l;
        }

        /* Decrement available bytes. */
        left -= elen;

        /* Update state for delta computation. */
        last = cur;
    }

    opts->enc_sz -= left;

    return 0;
err:
    return -1;
}

ec_rc_t ec_opts_decode(ec_opts_t *opts, const uint8_t *pdu, size_t pdu_sz, 
        uint8_t oc, size_t *olen)
{
    ec_opt_sym_t sym;
    unsigned char skip_this;
    size_t opt_len, opt_num = 0;
    unsigned int opt_count;
    const uint8_t *opt_p;
    ec_rc_t rc = EC_INTERNAL_SERVER_ERROR;

    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (pdu_sz < EC_COAP_HDR_SIZE, -1);
    dbg_return_if (opts == NULL, -1);
    dbg_return_if (olen == NULL, -1);

    *olen = 0;

    if ((opt_count = oc) == 0)
        return 0;

    opt_p = pdu + EC_COAP_HDR_SIZE;

    for (; opt_count > 0; opt_count--)
    {
        /* A priori, all options are equal.  While processing them, though,
         * we'll discover that some are more equal than others (unrecognized
         * elective options and fence-posts will assert this flag.) */
        skip_this = 0;

        /* Read delta and deduce option number. */ 
        opt_num += (*opt_p >> 4);

        switch ((sym = ec_opt_num2sym(opt_num)))
        {
            case EC_OPT_PROXY_URI:
            case EC_OPT_CONTENT_TYPE:
            case EC_OPT_MAX_AGE:
            case EC_OPT_ETAG:
            case EC_OPT_URI_HOST:
            case EC_OPT_LOCATION_PATH:
            case EC_OPT_URI_PORT:
            case EC_OPT_LOCATION_QUERY:
            case EC_OPT_URI_PATH:
            case EC_OPT_OBSERVE:
            case EC_OPT_TOKEN:
            case EC_OPT_ACCEPT:
            case EC_OPT_IF_MATCH:
            case EC_OPT_URI_QUERY:
            case EC_OPT_BLOCK2:
            case EC_OPT_BLOCK1:
            case EC_OPT_IF_NONE_MATCH:
                break;
            case EC_OPT_NONE:
            case EC_OPT_MAX:
            default:
                /* Unrecognized options of class "critical" that occur in 
                 * a confirmable request MUST cause the return of a 4.02 
                 * (Bad Option) response.  This response SHOULD include a 
                 * human-readable error message describing the unrecognized
                 * option(s). (Even option number == critical.) */
                if (opt_num % 2)
                {
                    u_dbg("unknown Critical Option %zu", opt_num);
                    rc = EC_BAD_OPTION;
                    goto err;
                }
                else
                {
                    skip_this = 1;
                    break;
                }
        }

        /* Read length (base or extended.) */
        if ((opt_len = (*opt_p & 0x0f)) == 0x0f)
            opt_len = *(opt_p + 1) + 15;

        /* The Option Numbers 14, 28, 42, ... are reserved for no-op options 
         * when they are sent with an empty value (they are ignored) and can 
         * be used as "fenceposts" if deltas larger than 15 would otherwise 
         * be required. */
        if (opt_len == 0 && EC_OPT_NUM_IS_FENCEPOST(opt_num))
            skip_this = 1;

        /* Jump over the lenght indicators to get to the option value. */
        opt_p += ((opt_len > 15) ? 2 : 1);

        /* Extract option and add it to the pool. */
        if (!skip_this)
            dbg_err_if (ec_opts_add(opts, sym, opt_p, opt_len));

        /* Jump over this option's value and come again. */
        opt_p += opt_len;
    }

    /* Set payload offset. */
    *olen = opt_p - (pdu + EC_COAP_HDR_SIZE); 

    return EC_RC_UNSET;
err:
    return rc;
}

u_uri_t *ec_opts_compose_url(ec_opts_t *opts, struct sockaddr_storage *us,
        bool nosec)
{
    u_uri_t *u;
    char url[U_URI_STRMAX];

    dbg_return_if (opts == NULL, NULL);

    /* [Proxy-URI] MAY occur one or more times and MUST take precedence over 
     * any of the Uri-Host, Uri-Port, Uri-Path or Uri-Query options. */
    if ((u = compose_proxy_uri(opts, url)) == NULL)
        dbg_err_if ((u = compose_uri(opts, us, nosec, url)) == NULL);

    return u;
err:
    return NULL;
}

/* It MUST NOT occur more than once. */
int ec_opts_get_content_type(ec_opts_t *opts, uint16_t *ct)
{
    uint64_t tmp;

    dbg_return_if (opts == NULL, -1);
    dbg_return_if (ct == NULL, -1);

    if (ec_opts_get_uint(opts, EC_OPT_CONTENT_TYPE, &tmp))
        return -1;

    dbg_err_ifm (tmp > UINT16_MAX, "Content-Type encoding overflow");

    *ct = (uint16_t) tmp;

    return 0;
err:
    return -1;
}

int ec_opts_get_block1(ec_opts_t *opts, uint32_t *num, bool *more,
        uint8_t *szx)
{
    return ec_opts_get_block(opts, num, more, szx, EC_OPT_BLOCK1);
}

int ec_opts_get_block2(ec_opts_t *opts, uint32_t *num, bool *more,
        uint8_t *szx)
{
    return ec_opts_get_block(opts, num, more, szx, EC_OPT_BLOCK2);
}

/* "It MAY NOT occur more than once" seems suggesting that we should be as
 * tolerant as possible with duplicates. */
int ec_opts_get_if_none_match(ec_opts_t *opts)
{
    dbg_return_if (opts == NULL, -1);

    return ec_opts_get(opts, EC_OPT_IF_NONE_MATCH) ? 0 : -1;
}

/* "The Observe Option MUST NOT occur more than once in a request or 
 * response." (we are liberal on receiving) */
int ec_opts_get_observe(ec_opts_t *opts, uint16_t *obs)
{
    uint64_t tmp;

    dbg_return_if (opts == NULL, -1);

    if (ec_opts_get_uint(opts, EC_OPT_OBSERVE, &tmp))
        return -1;

    dbg_err_ifm (tmp > UINT16_MAX, "Observe encoding overflow");

    if (obs)
        *obs = (uint16_t) tmp;

    return 0;
err:
    return -1;
}

int ec_opts_get_max_age(ec_opts_t *opts, uint32_t *max_age)
{
    uint64_t tmp;

    dbg_return_if (opts == NULL, -1);
    dbg_return_if (max_age == NULL, -1);

    if (ec_opts_get_uint(opts, EC_OPT_MAX_AGE, &tmp))
        return -1;

    dbg_err_ifm (tmp > UINT32_MAX, "Max-age encoding overflow");

    *max_age = (uint32_t) tmp;

    return 0;
err:
    return -1;
}

/* It MUST NOT occur more than once in a response, and MAY occur one or more 
 * times in a request. 
 * TODO rephrase this routine to resemble ec_opts_get_accept_all(). */
uint8_t *ec_opts_get_etag_nth(ec_opts_t *opts, size_t *etag_sz, size_t n)
{
    ec_opt_t *o;

    dbg_return_if (opts == NULL, NULL);
    dbg_return_if (etag_sz == NULL, NULL);

    if ((o = ec_opts_get_nth(opts, EC_OPT_ETAG, n)) == NULL)
        return NULL;

    *etag_sz = o->l;

    return o->v;
}

int ec_opts_get_accept_all(ec_opts_t *opts, ec_mt_t *mta, size_t *mta_sz)
{
    ec_opt_t *o;
    uint64_t mt;
    size_t nfound = 0;

    dbg_return_if (opts == NULL, -1);
    dbg_return_if (mta == NULL, -1);
    dbg_return_if (mta_sz == NULL || *mta_sz == 0, -1);

    TAILQ_FOREACH(o, &opts->bundle, next)
    {
        if (o->sym == EC_OPT_ACCEPT)
        {
            dbg_return_if (ec_opt_decode_uint(o->v, o->l, &mt), -1);

            mta[nfound] = (ec_mt_t) mt;

            if (++nfound == *mta_sz)
                break;
        }
    }

    *mta_sz = nfound;

    return 0;
}

int ec_opts_init(ec_opts_t *opts)
{
    dbg_return_if (opts == NULL, -1);

    memset(opts, 0, sizeof *opts);
    TAILQ_INIT(&opts->bundle);

    return 0;
}

static u_uri_t *compose_uri(ec_opts_t *opts, struct sockaddr_storage *us, 
        bool nosec, char uri[U_URI_STRMAX])
{
    u_uri_t *u = NULL;
    ec_opt_t *o;
    char host[U_URI_STRMAX], port[U_URI_STRMAX], path[U_URI_STRMAX],
         query[U_URI_STRMAX], authority[U_URI_STRMAX];

    dbg_return_if (opts == NULL, NULL);
    dbg_return_if (uri == NULL, NULL);
    dbg_return_if (us == NULL, NULL);
   
    /* Initialize tokens to empty. */
    host[0] = port[0] = path[0] = query[0] = authority[0] = '\0';

    TAILQ_FOREACH(o, &opts->bundle, next)
    {
        /* 
         * XXX verify the following...
         * Spec says: "Uri-Host and Uri-Port MUST NOT occur more than once".
         * Here this is relaxed to ignore possible duplicates.
         */

        if (o->sym >= EC_OPT_URI_HOST
                && host[0] == '\0'
                && authority[0] == '\0')
        {
            /* Check whether there is no explicit Uri-Host. */
            if (o->sym > EC_OPT_URI_HOST)
            {
                char a[sizeof host]; 
                const char *ap;

                /* "The default value of the Uri-Host Option is the IP literal
                 *  representing the destination IP address of the request 
                 *  message" */
                ap = evutil_format_sockaddr_port((struct sockaddr *) us,
                        a, sizeof a);

                /* Cook the whole meal (address and port) at once. */ 
                dbg_err_if (u_strlcpy(authority, ap, sizeof authority));
            }
            else
            {
                dbg_err_if (u_strlcpy(host, (const char *) o->v, sizeof host));
            }
        }

        /* Give precedence to authority, in case it was set by the Uri-Host
         * handler. */
        if (o->sym >= EC_OPT_URI_PORT
                && port[0] == '\0' 
                && authority[0] == '\0')
        {
            uint64_t p;
            const struct sockaddr *sa = (const struct sockaddr *) us;
            const struct sockaddr_in6 *s6;
            const struct sockaddr_in *s4;

            /* "[...] the default value of the Uri-Port Option is the 
             *  destination UDP port." */
            if (o->sym != EC_OPT_URI_PORT)
            {
                switch (sa->sa_family)
                {
                    case AF_INET6:
                        s6 = (const struct sockaddr_in6 *) sa;
                        p = ntohs(s6->sin6_port);
                        break;
                    case AF_INET:
                        s4 = (const struct sockaddr_in *) sa;
                        p = ntohs(s4->sin_port);
                        break;
                    default:
                        dbg_err("Unsupported address family");
                }
            }
            else
                dbg_err_if (ec_opt_decode_uint(o->v, o->l, &p));

            dbg_err_if (u_snprintf(port, sizeof port, "%llu", p));
        }

        if (o->sym == EC_OPT_URI_PATH)
        {
            dbg_err_if (u_strlcat(path, "/", sizeof path));
            dbg_err_if (u_strlcat(path, (const char *) o->v, sizeof path));
        }

        if (o->sym == EC_OPT_URI_QUERY)
        {
            if (query[0] != '\0')
                dbg_err_if (u_strlcat(query, "&", sizeof query));

            dbg_err_if (u_strlcat(query, (const char *) o->v, sizeof query));
        }
    }

    /* Assemble the URI from tokens. */
    dbg_err_if (u_uri_new(0, &u));

    (void) u_uri_set_scheme(u, nosec ? "coap" : "coaps");

    if (authority[0] == '\0')
    {
        (void) u_uri_set_host(u, host);
        (void) u_uri_set_port(u, port);
    }
    else
        (void) u_uri_set_authority(u, authority);

    (void) u_uri_set_path(u, path[0] == '\0' ? "/" : path);

    if (query[0] != '\0')
        (void) u_uri_set_query(u, query);

    dbg_err_if (u_uri_knead(u, uri));

    return u;
err:
    if (u)
        u_uri_free(u);
    return NULL;
}

static u_uri_t *compose_proxy_uri(ec_opts_t *opts, char uri[U_URI_STRMAX])
{
    ec_opt_t *o;
    u_uri_t *u = NULL;

    dbg_return_if (opts == NULL, NULL);
    dbg_return_if (uri == NULL, NULL);

    uri[0] = '\0';

    /* "Proxy-URI MAY occur one or more times and MUST take precedence over
     * any of the Uri-Host, Uri-Port, Uri-Path or Uri-Query options." */
    TAILQ_FOREACH(o, &opts->bundle, next)
    {
        /* Reassemble all Proxy-URI fragments. */
        if (o->sym == EC_OPT_PROXY_URI)
            dbg_err_if (u_strlcat(uri, (const char *) o->v, U_URI_STRMAX));
    }
 
    dbg_err_if (strlen(uri) == 0);
    dbg_err_if (u_uri_crumble(uri, 0, &u));

    return u;
err:
    if (u)
        u_uri_free(u);
    return NULL;
}

static uint8_t *add_fenceposts(ec_opts_t *opts, uint8_t *p, size_t cur, 
        size_t *delta)
{
    size_t opt_num, last = cur - *delta;

    for (opt_num = last; opt_num < cur; ++opt_num)
    {
        if (EC_OPT_NUM_IS_FENCEPOST(opt_num))
        {
            *p++ = (opt_num - last) << 4;

            /* Update last to the last FP. */
            last = opt_num;

            /* Increment the number of options coherently. */
            ++opts->noptions;
        }
    }

    /* Update delta. */
    *delta = cur - last;

    return p;
}

/* Compute how much buffer space is used by fenceposts. */
static size_t fenceposts_encsz(size_t cur, size_t last)
{
    size_t i, fpsz = 0;

    for (i = last; i < cur; ++i)
    {
        if (EC_OPT_NUM_IS_FENCEPOST(i))
            fpsz += 1;  /* Each FP consumes 1 byte. */
    }

    return fpsz;
}

int ec_opts_add_block(ec_opts_t *opts, ec_opt_sym_t which, uint32_t num, 
        bool more, uint8_t szx)
{
    uint32_t b = 0;

    dbg_return_if (opts == NULL, -1);
    dbg_return_if (which != EC_OPT_BLOCK1 && which != EC_OPT_BLOCK2, -1);

    /* Trim unsigned integer size to 20-bit. */
    dbg_return_if (num > 0xfffff, -1);

    /* The value 7 for SZX (which would indicate a block size of 2048) is 
     * reserved, i.e. MUST NOT be sent and MUST lead to a 4.00 Bad Request
     * response code upon reception in a request. */
    dbg_return_if (szx > 0x7, -1);

    b = szx;
    b |= (more ? 1 : 0) << 3;
    b |= num << 4;

    return ec_opts_add_uint(opts, which, b);
}

int ec_opts_get_block(ec_opts_t *opts, uint32_t *num, bool *more,
        uint8_t *szx, ec_opt_sym_t which)
{
    uint64_t tmp;

    dbg_return_if (opts == NULL, -1);
    dbg_return_if (num == NULL, -1);
    dbg_return_if (more == NULL, -1);
    dbg_return_if (szx == NULL, -1);
    dbg_return_if (which != EC_OPT_BLOCK1 && which != EC_OPT_BLOCK2, -1);

    if (ec_opts_get_uint(opts, which, &tmp))
        return -1;

    dbg_err_ifm (tmp > 0xffffff, "Block encoding overflow");

    *szx = tmp & 0x7;
    *more = tmp & 0x8;
    *num = tmp >> 4;

    return 0;
err:
    return -1;
}

