#include <u/libu.h>
#include "kache_evcoap.h"

//TODO : 
//       Why 3600 in ec_opts_get_max_age ../newrepo/webthings/bridge/sw/lib/evcoap/src/evcoap_opt.c :933


int init_fake_pdu(ec_pdu_t **p)
{
    ec_pdu_t *pdu;
    dbg_err_if((pdu = malloc(sizeof(ec_pdu_t))) == NULL);
    *p = pdu;
    dbg_err_if(ec_pdu_init_options(pdu));

    return 0; 
err:
    return -1;
}

int init_fake_client( ec_client_t **c)
{
    ec_client_t *cli;
    dbg_err_if((cli = malloc(sizeof(ec_client_t))) == NULL);
    *c = cli;

    // Tricking evcoap
    ec_conn_t* conn = &cli->flow.conn;
    conn->is_multicast = false;
    dbg_err_if(ec_res_set_init(&cli->res_set));

    return 0; 
err:
    return -1;

}


static int kache_evcoap_init_test(u_test_case_t *tc)
{
    kache_t *kache;
    dbg_err_if( (kache = kache_init()) == NULL);
    dbg_err_if( kache_init_data_structure(kache));
    struct event_base *base= event_base_new();
    kache_evcoap_t *ke;

    ke = kache_init_evcoap(kache,base);
    kache_free_evcoap(ke);
    free(base);
    kache_free(kache);
    
    return U_TEST_SUCCESS;
err:
    return U_TEST_FAILURE;
}

static int kache_evcoap_store_test(u_test_case_t *tc)
{
    kache_t *kache;
    dbg_err_if( (kache = kache_init()) == NULL);
    dbg_err_if( kache_init_data_structure(kache));
    struct event_base *base = event_base_new();
    kache_evcoap_t *ke;
    ke = kache_init_evcoap(kache,base);

    ec_client_t *cli;
    ec_pdu_t *pdu;
    dbg_err_if(init_fake_client(&cli));
    dbg_err_if(init_fake_pdu(&pdu));

    ec_opts_t *opts = &pdu->opts;

    dbg_err_if(ec_pdu_set_payload(pdu, (uint8_t *)"test-payload", 12));

    // Options
    dbg_err_if(ec_opts_add_content_type(opts, EC_MT_APPLICATION_LINK_FORMAT));
    dbg_err_if(ec_opts_add_max_age(opts, 40));
    dbg_err_if(ec_opts_add_etag(opts, (uint8_t *)"test", 4));
   
    // Add pdu to cli response set
    dbg_err_if(ec_res_set_add(&cli->res_set,pdu));

    dbg_err_if(kache_store_evcoap_response(ke,cli,"uri"));
    
    // Get from cache
    kache_obj_t *obj;
    obj = kache_get(kache,"uri");

    // Check if everything has been stored correctly
    u_test_err_if(obj == NULL);
    u_test_err_if(obj->protocol_type != COAP);
    u_test_err_if(strcmp(obj->key,"uri")!=0);
    
    kache_rep_t *rep;
    rep = kache_peak_rep(obj);
    u_test_err_if(rep == NULL);

    u_test_err_if(rep->media_type->type != KACHE_APPLICATION);
    u_test_err_if(rep->media_type->subtype != KACHE_LINK_FORMAT);
    u_test_err_if(strncmp((char *)rep->payload,"test-payload", 12) != 0);
    u_test_err_if(strncmp((char *)rep->ETag,"test", 4) != 0);
    u_test_err_if(rep->max_age != 40);

    // Overwrite

    ec_res_set_clear(&cli->res_set);
    //ec_pdu_free(pdu);
    dbg_err_if(init_fake_pdu(&pdu));
    opts = &pdu->opts;
    dbg_err_if(ec_opts_add_max_age(opts, 50));
    dbg_err_if(ec_opts_add_content_type(opts, EC_MT_APPLICATION_LINK_FORMAT));
    
    dbg_err_if(ec_res_set_add(&cli->res_set,pdu));

    dbg_err_if(kache_store_evcoap_response(ke,cli,"uri"));

    obj = kache_get(kache,"uri");

    rep = kache_peak_rep(obj);
    u_test_err_if(rep == NULL);
    u_test_err_if(rep->max_age != 50);

    kache_free_evcoap(ke);
    free(base);
    kache_free(kache);
    
    return U_TEST_SUCCESS;
err:
    return U_TEST_FAILURE;
}

static int kache_evcoap_timer_test(u_test_case_t *tc)
{
    kache_t *kache;
    dbg_err_if( (kache = kache_init()) == NULL);
    dbg_err_if( kache_init_data_structure(kache));
    struct event_base *base = event_base_new();
    kache_evcoap_t *ke;
    ke = kache_init_evcoap(kache,base);

    ec_client_t *cli;
    ec_pdu_t *pdu;
    dbg_err_if(init_fake_client(&cli));
    dbg_err_if(init_fake_pdu(&pdu));

    ec_opts_t *opts = &pdu->opts;
    dbg_err_if(ec_opts_add_max_age(opts, 1));

    dbg_err_if(ec_res_set_add(&cli->res_set,pdu));

    dbg_err_if(kache_store_evcoap_response(ke,cli,"uri"));
    kache_obj_t *obj;
    u_test_err_if((obj = kache_get(kache,"uri"))==NULL);
    event_base_loop(base,EVLOOP_ONCE);
    u_test_err_if((obj = kache_get(kache,"uri"))!=NULL);
    kache_free_evcoap(ke);
    free(base);
    kache_free(kache);

    return U_TEST_SUCCESS;
err:
    return U_TEST_FAILURE;
}

static int kache_evcoap_multiple_reps_test(u_test_case_t *tc)
{
    kache_t *kache;
    dbg_err_if( (kache = kache_init()) == NULL);
    dbg_err_if( kache_init_data_structure(kache));
    struct event_base *base = event_base_new();
    kache_evcoap_t *ke;
    ke = kache_init_evcoap(kache,base);

    ec_client_t *cli;
    ec_pdu_t *pdu;
    dbg_err_if(init_fake_client(&cli));
    dbg_err_if(init_fake_pdu(&pdu));

    ec_opts_t *opts = &pdu->opts;
    dbg_err_if(ec_opts_add_max_age(opts, 50));
    dbg_err_if(ec_opts_add_content_type(opts, EC_MT_TEXT_PLAIN));
    dbg_err_if(ec_res_set_add(&cli->res_set,pdu));
    dbg_err_if(kache_store_evcoap_response(ke,cli,"uri"));

    ec_res_set_clear(&cli->res_set);

    dbg_err_if(init_fake_pdu(&pdu));
    opts = &pdu->opts;
    dbg_err_if(ec_opts_add_max_age(opts, 40));
    dbg_err_if(ec_opts_add_content_type(opts, EC_MT_APPLICATION_LINK_FORMAT));
    dbg_err_if(ec_res_set_add(&cli->res_set,pdu));
    dbg_err_if(kache_store_evcoap_response(ke,cli,"uri"));


    kache_obj_t *obj;
    u_test_err_if((obj = kache_get(kache,"uri"))==NULL);
    kache_content_type_t *media_type;
    media_type = malloc(sizeof(kache_content_type_t));
    media_type->type = KACHE_TEXT;
    media_type->subtype = KACHE_PLAIN;
    kache_rep_t *rep;
    rep = kache_get_rep_by_media_type(obj,media_type);
    u_test_err_if(rep==NULL);
    u_test_err_if(rep->max_age!=50);
    media_type->type = KACHE_APPLICATION;
    media_type->subtype = KACHE_LINK_FORMAT;
    rep = kache_get_rep_by_media_type(obj,media_type);
    u_test_err_if(rep==NULL);
    u_test_err_if(rep->max_age!=40);

    kache_free_evcoap(ke);
    free(base);
    kache_free(kache);

    return U_TEST_SUCCESS;
err:
    return U_TEST_FAILURE;
}

static int kache_evcoap_pdu_get_test(u_test_case_t *tc)
{
    kache_t *kache;
    dbg_err_if( (kache = kache_init()) == NULL);
    dbg_err_if( kache_init_data_structure(kache));
    struct event_base *base = event_base_new();
    kache_evcoap_t *ke;
    ke = kache_init_evcoap(kache,base);

    ec_client_t *cli;
    ec_pdu_t *pdu;
    dbg_err_if(init_fake_client(&cli));
    dbg_err_if(init_fake_pdu(&pdu));

    ec_opts_t *opts = &pdu->opts;
    dbg_err_if(ec_pdu_set_payload(pdu, (uint8_t *)"test-payload", 12));
    dbg_err_if(ec_opts_add_max_age(opts, 40));
    dbg_err_if(ec_opts_add_content_type(opts, EC_MT_APPLICATION_EXI));
    dbg_err_if(ec_opts_add_etag(opts, (uint8_t *)"test", 4));

    dbg_err_if(ec_res_set_add(&cli->res_set,pdu));
    dbg_err_if(kache_store_evcoap_response(ke,cli,"uri"));
    u_test_err_if((pdu = kache_get_evcoap_response(ke,cli,"uri-notincache"))!=NULL);
    u_test_err_if((pdu = kache_get_evcoap_response(ke,cli,"uri"))==NULL);

    opts = &pdu->opts;
    ev_uint8_t *pl;
    ev_uint16_t ct;
    uint8_t *etag;
    //Content type
    ec_opts_get_content_type(
                opts, 
                &ct);

    u_test_err_if(ct!=EC_MT_APPLICATION_EXI);
    //Payload
    u_test_err_if(strncmp("test-payload",(char*)pdu->payload,pdu->payload_sz)!=0);
    //Max Age
    unsigned int max_age;
    ec_opts_get_max_age(opts, &max_age);
    u_test_err_if(max_age!=40);

    kache_free_evcoap(ke);
    free(base);
    kache_free(kache);


    return U_TEST_SUCCESS;
err:
    return U_TEST_FAILURE;
}
int test_suite_kache_evcoap_register(u_test_t *t)
{
    u_test_suite_t *ts = NULL;

    dbg_err_if (u_test_suite_new("Kache evcoap", &ts));
    dbg_err_if (u_test_case_register("kache_evcoap_init_test", kache_evcoap_init_test, ts));
    dbg_err_if (u_test_case_register("kache_evcoap_store_test", kache_evcoap_store_test, ts));
    dbg_err_if (u_test_case_register("kache_evcoap_timer_test", kache_evcoap_timer_test, ts));
    dbg_err_if (u_test_case_register("kache_evcoap_multiple_reps_test", kache_evcoap_multiple_reps_test, ts));
    dbg_err_if (u_test_case_register("kache_evcoap_pdu_get_test", kache_evcoap_pdu_get_test, ts));

    /* No dependencies. */

    return u_test_suite_add(ts, t);
err:
    u_test_suite_free(ts);
    return -1;
}
