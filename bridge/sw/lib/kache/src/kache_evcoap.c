#include "kache_evcoap.h"

void kache_evcoap_timer_cb(int i, short e,void *arg);
int kache_store_ec_options_in_rep(ec_opts_t *opts, kache_rep_t *rep);
int kache_ct_from_ecct(kache_content_type_t *mt, ev_uint16_t *ct);

//TODO Backward translation

kache_evcoap_t *kache_init_evcoap(kache_t *kache, struct event_base *base)
{
    kache_evcoap_t *ke;
    dbg_err_if((ke = malloc(sizeof(kache_evcoap_t))) == NULL);
    ke->base = base;
    ke->kache = kache;
    return ke;
err:
    return NULL;
}

void kache_free_evcoap(kache_evcoap_t *ke)
{
    //TODO free kache and event_base?
    u_free(ke);
}

kache_evcoap_data_t *kache_init_evcoap_data()
{
    kache_evcoap_data_t *data;
    data = malloc(sizeof(kache_evcoap_data_t));
    return data;
}
void kache_free_evcoap_data(kache_evcoap_data_t *data)
{
    if (data)
        u_free(data);
}


int kache_store_evcoap_response(kache_evcoap_t *ke, ec_client_t *cli)
{
    dbg_return_if (ke == NULL, -1);
    dbg_return_if (cli == NULL, -1);
    ec_rc_t rc;
    kache_obj_t *obj = NULL;
    kache_rep_t *rep = NULL;
    ec_opts_t *opts = ec_client_get_response_options(cli);
    size_t pl_sz;
    size_t etag_sz;
    ev_uint8_t *pl;
    ev_uint16_t ct;
    uint8_t *etag;
    uint32_t max_age;

    obj = kache_get(ke->kache,"uri"); //TODO uri?

    //Content type
    dbg_err_if(ec_opts_get_content_type(
                opts, 
                &ct)
            );
    kache_content_type_t *mt;
    dbg_err_if((mt = malloc(sizeof(kache_content_type_t)))==NULL);
    kache_ct_from_ecct(mt,&ct);

    // Check if there is already a corresponding representation
    // and delete it
    if(obj)
    {
        rep = kache_get_rep_by_media_type(obj,mt);
        if(rep)
        {
            (void) kache_remove_rep(obj,rep);
            kache_clear_kache_rep(rep);
        }
        else
            dbg_err_if( (rep = kache_init_kache_rep()) == NULL);

    }
    else
    {
        dbg_err_if((obj = kache_init_kache_obj()) == NULL);

        //placeholder
        obj->key = malloc(4);
        strcpy(obj->key,"uri");

        obj->protocol_type = COAP;
        dbg_err_if( (rep = kache_init_kache_rep()) == NULL);
    }
    rep->media_type = mt;
    // Constructing the cached resource representation

    // Payload
    pl = ec_response_get_payload(cli, &pl_sz);
    dbg_err_if((rep->payload = malloc(pl_sz )) == NULL);
    memcpy(rep->payload, pl, pl_sz);
    rep->payload_size = pl_sz;

    // ts
    dbg_err_if( (rep->ts = u_zalloc(sizeof(struct timeval))) == NULL );
    dbg_err_if( gettimeofday(rep->ts,NULL) );

    // Other options
    
    dbg_err_if(kache_store_ec_options_in_rep(opts,rep));

    //max_age
    if(rep->max_age == 0)
        rep->max_age = 60;
    max_age = rep->max_age;

    //Timer
    kache_timer_arg_t *arg;
    dbg_err_if((arg = malloc(sizeof(kache_timer_arg_t)))==NULL);
    arg->rep = rep;
    arg->obj = obj;
    kache_set_rep_timer(ke->base,
            rep,
            max_age,
            kache_evcoap_timer_cb,
            (void *) arg
            );
    //Per protocol data (placeholder)
    kache_evcoap_data_t *data;
    data = kache_init_evcoap_data();
    rep->per_protocol_data = data;
    
    //Add representation to obj
    dbg_err_if(kache_add_rep(obj,rep));
    kache_obj_t *overwrite;
    kache_set(ke->kache,"uri",obj,&overwrite);
    return 0;
err:
    if(obj)
        free(obj);
    if(rep)
        free(rep);
    return -1;
}

void kache_evcoap_timer_cb(int i, short e,void *arg)
{
    //PH
    kache_obj_t *obj;
    kache_timer_arg_t *a = (kache_timer_arg_t*) arg;
    obj = a->obj;
    kache_rep_t *rep;
    rep = a->rep;
    kache_remove_rep(obj,rep);
    kache_evcoap_data_t *data;
    kache_free_kache_rep_with_data(rep,(void **) &data);
    kache_free_evcoap_data(data);
}

int kache_store_ec_options_in_rep(ec_opts_t *opts, kache_rep_t *rep)
{
    ec_opt_sym_t sym;

    dbg_return_if (opts == NULL, -1);
    dbg_return_if (rep == NULL, -1);

    /* Looping this way instead of FOREACH'ing over the opts is 
     * less efficient, but lets us do deep inspection on forwarded
     * Options, which may be useful in case any mapping policy is
     * taken into consideration at a further stage. */
    for (sym = EC_OPT_NONE + 1; sym < EC_OPT_MAX; ++sym)
    {
        switch (sym)
        {
            /* Really not expected in a response. */
            case EC_OPT_PROXY_URI:
            case EC_OPT_URI_HOST:
            case EC_OPT_URI_PORT:
            case EC_OPT_URI_PATH:
            case EC_OPT_URI_QUERY:
            case EC_OPT_ACCEPT:
            case EC_OPT_IF_MATCH:
            case EC_OPT_IF_NONE_MATCH:
                //TODO check what to do with the following
            case EC_OPT_PUBLISH:
            case EC_OPT_LOCATION_PATH:
            case EC_OPT_LOCATION_QUERY:
            case EC_OPT_CONTENT_TYPE:
            {
                //Media type has been already handled
                break;
            }

            case EC_OPT_MAX_AGE:
            {

                ec_opts_get_max_age(opts, &rep->max_age);
                break;
            }

            case EC_OPT_ETAG:
            {
                uint8_t *et;
                size_t et_sz;
                size_t i = 0;

                /* It MUST NOT occur more than once in a response. */
                if((et = ec_opts_get_etag_nth(opts, &et_sz, 0))!=NULL)
                {
                    dbg_err_if((rep->ETag = malloc(et_sz + 1)) == NULL);
                    memcpy(rep->ETag,et,et_sz);
                    rep->ETag[et_sz] = '\0';
                }
                break;
            }

            case EC_OPT_OBSERVE:
            {
                break;
            }

            case EC_OPT_TOKEN:
            {
                uint8_t *token;
                size_t token_sz;

                /* It MUST NOT occur more than once. */
                //TODO enum sortof?
                if ((token = ec_opts_get_token(opts, &token_sz)) != NULL)
                    dbg_if(kache_add_key_val(rep, 
                                "Token", 
                                5,
                                (char*) token,
                                token_sz));
                break;
            }
            //TODO: block?
            case EC_OPT_BLOCK2:
            {
                /*uint8_t szx;
                bool more;
                uint32_t num;

                if (ec_opts_get_block2(opts, &num, &more, &szx) == 0)
                    dbg_if (ec_opts_add_block2(dst, num, more, szx));*/
                break;
            }

            case EC_OPT_BLOCK1:
            {
                /*uint8_t szx;
                bool more;
                uint32_t num;

                if (ec_opts_get_block1(src, &num, &more, &szx) == 0)
                    dbg_if (ec_opts_add_block1(dst, num, more, szx));*/
                break;
            }

            default:
                break;
        }
    }

    return 0;
err:
    return -1;
}
int kache_ct_from_ecct(kache_content_type_t *mt, ev_uint16_t *ct)
{
    switch ((int) *ct) {

        case EC_MT_TEXT_PLAIN:
            mt->type=KACHE_TEXT;
            mt->subtype=KACHE_PLAIN;
            break;
        case EC_MT_APPLICATION_LINK_FORMAT:
            mt->type=KACHE_APPLICATION;
            mt->subtype=KACHE_LINK_FORMAT;
            break;
        case EC_MT_APPLICATION_XML:
            mt->type=KACHE_APPLICATION;
            mt->subtype=KACHE_XML;
            break;
        case EC_MT_APPLICATION_OCTET_STREAM:
            mt->type=KACHE_APPLICATION;
            mt->subtype=KACHE_OCTET_STREAM;
            break;
        case EC_MT_APPLICATION_EXI:
            mt->type=KACHE_APPLICATION;
            mt->subtype=KACHE_EXI;
            break;
        case EC_MT_APPLICATION_JSON:
            mt->type=KACHE_APPLICATION;
            mt->subtype=KACHE_JSON;
            break;
        default:
            mt->type=KACHE_APPLICATION;
            mt->subtype=KACHE_XML;
    }
    return 0;

}


