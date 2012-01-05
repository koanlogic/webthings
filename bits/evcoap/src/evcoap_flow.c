#include "evcoap_flow.h"

int ec_flow_save_token(ec_flow_t *flow, ev_uint8_t *tok, size_t tok_sz)
{
    dbg_return_if (flow == NULL, -1);

    if (tok == NULL && tok_sz == 0)
    {
        memset(flow->token, 0, sizeof flow->token);
        flow->token_sz = 0;
    }

    return 0;
}
