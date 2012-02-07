#include <u/libu.h>
#include "evcoap_filesys.h"

#define TEST_URI    "coap://my.thing./s/light"
#define TEST_MAXAGE 1200
#define TEST_DATA_0 "data_0"
#define TEST_DATA_1 "data_1"
#define TEST_MEDIA_TYPE EC_MT_TEXT_PLAIN

struct xyz {
    const char *uri;
    ev_uint32_t max_age;
    const char *data;
    ec_mt_t media_type;
    ev_uint8_t etag[EC_ETAG_SZ];    /* Result argument. */
} res_set[] = {
    { 
        .uri = "coap://my.thing./s/txt",  
        .max_age = 1200,
        .data = "plain text",
        .media_type = EC_MT_TEXT_PLAIN
    },
    { 
        .uri = "coap://my.thing./s/xml",
        .max_age = 30,
        .data = "<tag />",
        .media_type = EC_MT_APPLICATION_XML
    },
    { 
        .uri = "coap://my.thing./s/json",
        .max_age = 86400,
        .data = "a: \"true\"",
        .media_type = EC_MT_APPLICATION_JSON
    }
};
#define RES_SET_CARDINALITY (sizeof res_set / sizeof(struct xyz))

static int put_res(ec_filesys_t *fs, u_test_case_t *tc, const char *uri,
        ev_uint32_t max_age, const ev_uint8_t *data, size_t data_sz, 
        ec_mt_t media_type, ev_uint8_t etag[EC_ETAG_SZ])
{
    ec_filesys_res_t *res = NULL;
    
    /* Create new resource. */
    u_test_err_ifm(!(res = ec_filesys_new_resource(uri, max_age)),
            "resource creation failed");

    /* Add representation to resource. */
    u_test_err_ifm (ec_filesys_add_rep(res, data, data_sz, 
                media_type, etag), "adding representation failed");

    /* Insert resource into the file system. */
    u_test_err_ifm (ec_filesys_put_resource(fs, res), "adding resource failed");
    res = NULL; /* ownership lost */

    return 0;
err:
    if (res)
        ec_filesys_free_resource(res);
    return -1;
}

static int insert_all(ec_filesys_t *fs, u_test_case_t *tc)
{
    int rc;
    size_t i;
    ec_filesys_res_t *res = NULL;

    for (i = 0; i < RES_SET_CARDINALITY; ++i)
    {
        rc = put_res(fs, tc, res_set[i].uri, res_set[i].max_age,
                (const ev_uint8_t *) res_set[i].data, 
                strlen(res_set[i].data) + 1, res_set[i].media_type,
                res_set[i].etag);

        u_test_err_ifm (rc != 0, "inserting resource %zu failed");
    }

    return 0;
err:
    if (res)
        ec_filesys_free_resource(res);
    return -1;
}

static int lookup_all(ec_filesys_t *fs, u_test_case_t *tc)
{
    size_t i;
    ec_filesys_rep_t *rep;

    for (i = 0; i < RES_SET_CARDINALITY; ++i)
    {
        rep = ec_filesys_get_rep(fs, res_set[i].uri, 
                res_set[i].media_type, res_set[i].etag);

        u_test_err_ifm (rep == NULL, "%s not found", res_set[i].uri);

        u_test_err_ifm (strcmp((const char *) rep->data, res_set[i].data), 
                "data mismatch at %s: '%s' vs '%s'", res_set[i].uri,
                rep->data, res_set[i].data);
    }

    return 0;
err:
    return -1;
}


static int iur(ec_filesys_t *fs, u_test_case_t *tc)
{
    int rc;
    ec_filesys_rep_t *rep;
    ev_uint8_t etag[EC_ETAG_SZ];

    /* Create resource with initial content. */
    rc = put_res(fs, tc, TEST_URI, TEST_MAXAGE, 
            (const ev_uint8_t *) TEST_DATA_0, strlen(TEST_DATA_0) + 1, 
            TEST_MEDIA_TYPE, etag);

    u_test_err_ifm (rc != 0, "inserting resource %zu failed");

   
    /* Update representation. */
    rc = put_res(fs, tc, TEST_URI, TEST_MAXAGE, 
            (const ev_uint8_t *) TEST_DATA_1, strlen(TEST_DATA_1) + 1, 
            TEST_MEDIA_TYPE, etag);

    /* Get updated value. */
    rep = ec_filesys_get_rep(fs, TEST_URI, TEST_MEDIA_TYPE, etag);
    u_test_err_ifm (rep == NULL, "%s not found", TEST_URI);

    u_test_err_ifm (strcmp((const char *) rep->data, TEST_DATA_1), 
            "data mismatch at %s: '%s' vs '%s'", TEST_URI, rep->data, 
            TEST_DATA_1);

    return 0;
err:
    return -1;
}

static int test_insert(u_test_case_t *tc)
{
    ec_filesys_t *fs = NULL;

    u_test_err_ifm (!(fs = ec_filesys_create()), "file system creation failed");

    u_test_err_if (insert_all(fs, tc));

    ec_filesys_destroy(fs);

    return U_TEST_SUCCESS;
err:
    if (fs)
        ec_filesys_destroy(fs);
    return U_TEST_FAILURE;
}

static int test_lookup(u_test_case_t *tc)
{
    ec_filesys_t *fs = NULL;

    u_test_err_ifm (!(fs = ec_filesys_create()), "file system creation failed");

    u_test_err_if (insert_all(fs, tc));
    u_test_err_if (lookup_all(fs, tc));

    ec_filesys_destroy(fs);

    return U_TEST_SUCCESS;
err:
    if (fs)
        ec_filesys_destroy(fs);
    return U_TEST_FAILURE;
}

static int test_update(u_test_case_t *tc)
{
    ec_filesys_t *fs = NULL;

    u_test_err_ifm (!(fs = ec_filesys_create()), "file system creation failed");

    u_test_err_if (iur(fs, tc));

    ec_filesys_destroy(fs);

    return U_TEST_SUCCESS;
err:
    if (fs)
        ec_filesys_destroy(fs);
    return U_TEST_FAILURE;
}

int test_suite_filesys_register(u_test_t *t)
{
    u_test_suite_t *ts = NULL;

    con_err_if (u_test_suite_new("File system", &ts));

    con_err_if (u_test_case_register("insert", test_insert, ts));
    con_err_if (u_test_case_register("lookup", test_lookup, ts));
    con_err_if (u_test_case_register("update", test_update, ts));

    /* No dependencies. */

    return u_test_suite_add(ts, t);
err:
    u_test_suite_free(ts);
    return -1;
}
