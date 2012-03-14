#include <u/libu.h>
#include "kache_pdu.h"


int kache_add_key_val(kache_pdu_t *pdu, char *key, char *val)
{
    kache_keyval_t *keyval;
    dbg_err_if((keyval = u_zalloc(sizeof(kache_keyval_t))) == NULL);
    TAILQ_INSERT_TAIL(&pdu->keyvalq, keyval, next);
    return 0;
err:
    return -1;
}

kache_pdu_t *kache_init_kache_pdu()
{
    kache_pdu_t *pdu = u_zalloc(sizeof(kache_keyval_t));
    TAILQ_INIT(&pdu->keyvalq);
    return pdu;
}

void kache_free_kache_keyval(kache_keyval_t *keyval)
{
    if(keyval)
    {
        u_free(keyval->key);
        u_free(keyval->value);
        u_free(keyval);
    }
}

void kache_free_kache_pdu(kache_pdu_t *pdu)
{
    kache_keyval_t *keyval;
    if(pdu)
    { 
        while ((keyval = TAILQ_FIRST(&pdu->keyvalq)))
        {
            TAILQ_REMOVE(&pdu->keyvalq, keyval, next);
            kache_free_kache_keyval(keyval);
        }
        u_free(pdu->payload);
        u_free(pdu->method);
        u_free(pdu->ETag);
        u_free(pdu->media_type);
        u_free(pdu->ts);
        u_free(pdu->payload);
        u_free(pdu->per_protocol_data);
        u_free(pdu->protocol_type);
        u_free(pdu);
    }
}

