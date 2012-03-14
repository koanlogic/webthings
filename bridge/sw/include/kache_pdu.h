#ifndef _KACHE_PDU_H_
#define _KACHE_PDU_H_

#include <sys/queue.h>


struct kache_keyval_s 
{
    char *key;
    char *value;
    TAILQ_ENTRY(kache_keyval_s) next;
};

typedef struct kache_keyval_s kache_keyval_t;

struct kache_pdu_s 
{
    TAILQ_HEAD(,  kache_keyval_s) keyvalq;
    int response_code;
    char *payload;
    size_t payload_size;
    char *method;
    char *ETag;
    char *media_type;
    struct timeval *ts;
    int max_age;
    void *per_protocol_data;
};

typedef struct kache_pdu_s kache_pdu_t;
kache_pdu_t *kache_init_kache_pdu();
int kache_add_key_val(kache_pdu_t *pdu, char *key, char *val);
void kache_free_kache_keyval(kache_keyval_t *keyval);
void kache_free_kache_pdu(kache_pdu_t *pdu);

#endif /* _KACHE_PDU_H_ */
