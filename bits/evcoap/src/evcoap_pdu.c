#include <u/libu.h>
#include "evcoap_pdu.h"

int ec_pdu_set_payload(ec_pdu_t *pdu, ev_uint8_t *payload, size_t sz)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (payload == NULL, -1);
    dbg_return_if (sz == 0, -1);

    dbg_return_sif ((pdu->payload = u_memdup(payload, sz)) == NULL, -1);
    pdu->payload_sz = sz;

    return 0;
}