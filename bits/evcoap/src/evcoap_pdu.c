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

int ec_pdu_set_flow(ec_pdu_t *pdu, ec_flow_t *flow)
{
    dbg_return_if (pdu == NULL, -1);

    pdu->parent_flow = flow;

    return 0;
}

int ec_pdu_init_options(ec_pdu_t *pdu)
{
    dbg_return_if (pdu == NULL, -1);

    TAILQ_INIT(&pdu->opts.bundle);
    pdu->opts.noptions = 0;

    return 0;
}

int ec_pdu_send(ec_pdu_t *pdu, const struct sockaddr_storage *dest)
{
    dbg_return_if (pdu == NULL, -1);
    dbg_return_if (dest == NULL, -1);

    /* TODO */

    return 0;
}

int ec_pdu_encode(ec_pdu_t *pdu)
{
    dbg_return_if (pdu == NULL, -1);

    /* TODO */

    return 0;
}
