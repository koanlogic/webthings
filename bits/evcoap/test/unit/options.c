#include <u/libu.h>
#include "evcoap_opt.h"

#define TEST_URI    "coap://[::1]:50505/.well-known/core"
#define LONG_URI   "http://a---------------------------------------------------very--------------------------------------long-------------------host------------------------name.a------------------------------very-----------------long---------------------------domain.com/a______________very_____________long____________path"

/* 
 * TODO test each option alone: 
 * TODO     - codec with mono and multi values
 * TODO     - cardinality (how many times it may be found)
 * TODO     - range (values space) boundaries
 */

static int test_codec(u_test_case_t *tc)
{
    ec_opts_t in, out;
    size_t enc_sz, olen, etag_sz;
    char urlstr[U_URI_STRMAX] = { '\0' };
    ev_uint16_t ct;
    ev_uint8_t etag[4] = { 0xde, 0xad, 0xbe, 0xef }, *etagp, oc,
               enc[EC_OPTS_MAX_LEN + EC_COAP_HDR_SIZE];

    /* Initialize options' sink. */
    ec_opts_init(&in);

    /* Push options. */
    u_test_err_if (ec_opts_add_content_type(&in, EC_MT_TEXT_PLAIN));
    u_test_err_if (ec_opts_add_max_age(&in, 3600));
    u_test_err_if (ec_opts_add_proxy_uri(&in, LONG_URI));
//    u_test_err_if (ec_opts_add_etag(&in, etag, sizeof etag));

    /* Encode to 'in'. */
    u_test_err_if (ec_opts_encode(&in));

    /* Save encoded value. */
    u_test_err_if ((enc_sz = in.enc_sz + EC_COAP_HDR_SIZE) > sizeof enc);
    memcpy(enc + EC_COAP_HDR_SIZE, in.enc, enc_sz);
    oc = in.noptions;

    ec_opts_init(&out);

    /* Decode to 'out'. */
    u_test_err_if (ec_opts_decode(&out, enc, enc_sz, oc, &olen));

    /* Content-Type */
    u_test_err_if (ec_opts_get_content_type(&out, &ct));
    u_test_err_ifm (ct != EC_MT_TEXT_PLAIN, "Expecting ct=text-plain");

    /* ETag */
//    u_test_err_if ((etagp = ec_opts_get_etag_nth(&out, &etag_sz, 0)) == NULL);
//    u_test_err_ifm (memcmp(etagp, etag, etag_sz), "ETag mismatch");

    /* Proxy-URI */
    u_test_err_if (ec_opts_get_proxy_uri(&out, urlstr) == NULL);
    u_test_err_ifm (strcmp(urlstr, LONG_URI), "%s != %s", urlstr, LONG_URI);

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

    con_err_if (u_test_case_register("encode/decode", test_codec, ts));

    /* No dependencies. */

    return u_test_suite_add(ts, t);
err:
    u_test_suite_free(ts);
    return -1;
}

