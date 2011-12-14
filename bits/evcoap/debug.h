#ifndef _EVCOAP_DEBUG_H_
#define _EVCOAP_DEBUG_H_

#include "evcoap.h"
#include "evcoap-internal.h"

void evcoap_dbg_print_hdr(const char *tag, const ev_uint8_t *hdr);
void evcoap_dbg_print_timeval(const char *tag, const struct timeval *tv);
void evcoap_dbg_print_buffer(const char *id, const ev_uint8_t *b, size_t blen);

#endif  /* !_EVCOAP_DEBUG_H_ */
