#include <u/libu.h>
#include "evcoap_opt.h"

#define TEST_URI    "coap://[::1]:50505/.well-known/core"

/* 
 * TODO test each option alone: 
 * TODO     - codec with mono and multi values
 * TODO     - cardinality (how many times it may be found)
 * TODO     - range (values space) boundaries
 */

const char *g_non_abs_uri = "//non/absolute/url";

const char *g_split_uri = "http://www.example.com/aaaaaaaaaaa/bbbbbbbbbbb/"
    "ccccccccccc/ddddddddddd/eeeeeeeeeee/fffffffffff/"
    "ggggggggggg/hhhhhhhhhhh/iiiiiiiiiii/lllllllllll/"
    "mmmmmmmmmmm/nnnnnnnnnnn/ooooooooooo/ppppppppppp/"
    "qqqqqqqqqqq/rrrrrrrrrrr/sssssssssss/ttttttttttt/"
    "uuuuuuuuuuu/vvvvvvvvvvv/zzzzzzzzzzz";

static int encdec(ec_opts_t *in, ec_opts_t *out)
{
    size_t enc_sz, olen;
    ev_uint8_t enc[EC_OPTS_MAX_LEN + EC_COAP_HDR_SIZE];

    con_err_if (ec_opts_encode(in));

    /* Save encoded value. */
    con_err_if ((enc_sz = in->enc_sz + EC_COAP_HDR_SIZE) > sizeof enc);
    memcpy(enc + EC_COAP_HDR_SIZE, in->enc, enc_sz);

    (void) ec_opts_init(out);

    /* Decode to 'out'. */
    con_err_if (ec_opts_decode(out, enc, enc_sz, in->noptions, &olen));

    return 0;
err:
    return -1;
}

static int test_proxy_uri(u_test_case_t *tc)
{
    ec_opts_t opts;

    (void) ec_opts_init(&opts);

    /* Non absolute URI are rejected (will not increment opts.noptions). */
    u_test_err_if (ec_opts_add_proxy_uri(&opts, g_non_abs_uri) == 0);

    /* Long URI is split in two options. */
    u_test_err_if (ec_opts_add_proxy_uri(&opts, g_split_uri));
    u_test_err_if (opts.noptions != 2);

    /* TODO encode/decode ? */

    ec_opts_clear(&opts);
    return U_TEST_SUCCESS;
err:
    ec_opts_clear(&opts);
    return U_TEST_FAILURE;
}

static int test_publish(u_test_case_t *tc)
{
    size_t i;
    ec_opts_t in, out;
    uint8_t mma[] = {
        [0] = (uint8_t) EC_METHOD_MASK_ALL,
        [1] = (uint8_t) EC_GET_MASK,
        [2] = (uint8_t) EC_PUT_MASK,
        [3] = (uint8_t) EC_POST_MASK,
        [4] = (uint8_t) EC_DELETE_MASK
    };

    (void) ec_opts_init(&in);
    (void) ec_opts_init(&out);

    for (i = 0; i < sizeof mma / sizeof(ec_method_mask_t); ++i)
    {
        uint8_t mm_out = 0;

        u_test_err_if (ec_opts_add_publish(&in, mma[i]));
        u_test_err_if (encdec(&in, &out));
        u_test_err_if (ec_opts_get_publish(&out, &mm_out));

        u_test_err_ifm (mma[i] != mm_out,
                "[%zu] exp(%u) != got(%u)", i, mma[i], mm_out);

        ec_opts_clear(&in);
        ec_opts_clear(&out);
    }

    return U_TEST_SUCCESS;
err:
    return U_TEST_FAILURE;
}

static int test_block(u_test_case_t *tc)
{
    size_t i;
    ec_opts_t in, out;
    struct tv {
        ev_uint32_t num;
        bool more;
        ev_uint8_t szx; 
    } tva[] = {
        { 1, true,  3 }, 
        { 2, false, 4 } 
    };

    for (i = 0; i < sizeof tva / sizeof(struct tv); ++i)
    {
        ev_uint32_t num;
        bool more;
        ev_uint8_t szx; 

        (void) ec_opts_init(&in);
        (void) ec_opts_init(&out);
        u_test_err_if (ec_opts_add_block1(&in, tva[i].num, tva[i].more,
                    tva[i].szx));
        u_test_err_if (encdec(&in, &out));
        u_test_err_if (ec_opts_get_block1(&out, &num, &more, &szx));
        ec_opts_clear(&in);
        ec_opts_clear(&out);

        u_con("%u, %u", num, tva[i].num);

        u_test_err_ifm (num != tva[i].num, "%u != %u", num, tva[i].num);
        u_test_err_ifm (more != tva[i].more, "%d != %d", more, tva[i].more);
        u_test_err_ifm (szx != tva[i].szx, "%u != %u", szx, tva[i].szx);
    }
 
    return U_TEST_SUCCESS;
err:
    ec_opts_clear(&in);
    ec_opts_clear(&out);

    return U_TEST_SUCCESS;
}

static int test_fencepost(u_test_case_t *tc)
{
    ev_uint16_t ct;
    ec_opts_t in, out;

    (void) ec_opts_init(&in);
    (void) ec_opts_init(&out);

    /* Push options. */
    u_test_err_if (ec_opts_add_content_type(&in, EC_MT_APPLICATION_JSON));

    /* (delta = (If-None-Match - Content-Type) == 20) => force fencepost */
    u_test_err_if (ec_opts_add_if_none_match(&in));

    u_test_err_if (encdec(&in, &out));

    /* Get If-None-Match and Content-Type. */
    u_test_err_if (ec_opts_get_if_none_match(&out));
    u_test_err_if (ec_opts_get_content_type(&out, &ct));

    /* Check if values match with input. */
    u_test_err_if (ct != EC_MT_APPLICATION_JSON);

    ec_opts_clear(&in);
    ec_opts_clear(&out);
 
    return U_TEST_SUCCESS;
err:
    ec_opts_clear(&in);
    ec_opts_clear(&out);

    return U_TEST_FAILURE;
}

static int test_codec_bunch(u_test_case_t *tc)
{
    ec_opts_t in, out;
    size_t etag_sz;
    char uri[U_URI_STRMAX] = { '\0' };
    ev_uint16_t ct;
    ev_uint8_t etag[4] = { 0xde, 0xad, 0xbe, 0xef }, *etagp;

    /* Initialize options' sink. */
    (void) ec_opts_init(&in);
    (void) ec_opts_init(&out);

    /* Push options. */
    u_test_err_if (ec_opts_add_content_type(&in, EC_MT_TEXT_PLAIN));
    u_test_err_if (ec_opts_add_max_age(&in, 3600));
    u_test_err_if (ec_opts_add_proxy_uri(&in, g_split_uri));
    u_test_err_if (ec_opts_add_etag(&in, etag, sizeof etag));

    /* Encode 'in' and decode to 'out'. */
    u_test_err_if (encdec(&in, &out));

    /* Pop options:
     *  - Content-Type
     *  - ETag
     *  - Proxy-URI */
    u_test_err_if (ec_opts_get_content_type(&out, &ct));
    u_test_err_if ((etagp = ec_opts_get_etag_nth(&out, &etag_sz, 0)) == NULL);
    u_test_err_if (ec_opts_get_proxy_uri(&out, uri) == NULL);

    /* Check options values. */
    u_test_err_ifm (ct != EC_MT_TEXT_PLAIN, "Content-Type != text-plain");
    u_test_err_ifm (memcmp(etagp, etag, etag_sz), "ETag mismatch");
    u_test_err_ifm (strcmp(uri, g_split_uri), "%s != %s", uri, g_split_uri);

    /* Everything done, clean up. */
    ec_opts_clear(&in);
    ec_opts_clear(&out);

    return U_TEST_SUCCESS;
err:
    ec_opts_clear(&in);
    ec_opts_clear(&out);

    return U_TEST_FAILURE;
}

int test_suite_options_register(u_test_t *t)
{
    u_test_suite_t *ts = NULL;

    con_err_if (u_test_suite_new("CoAP options", &ts));

    con_err_if (u_test_case_register("encode/decode", test_codec_bunch, ts));
    con_err_if (u_test_case_register("Proxy-URI", test_proxy_uri, ts));
    con_err_if (u_test_case_register("Fencepost", test_fencepost, ts));
    con_err_if (u_test_case_register("Block1/2", test_block, ts));
    con_err_if (u_test_case_register("Publish", test_publish, ts));

    /* No dependencies. */

    return u_test_suite_add(ts, t);
err:
    u_test_suite_free(ts);
    return -1;
}

