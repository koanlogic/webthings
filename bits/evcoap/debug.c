#include "evcoap.h"
#include "evcoap-internal.h"

void evcoap_dbg_print_hdr(const char *tag, const ev_uint8_t *hdr)
{
    size_t i;

    printf("%s: ", tag);
    for (i = 0; i < 4; i++)
        printf("%02x ", hdr[i]);
    printf("\n");
}

void evcoap_dbg_print_timeval(const char *tag, const struct timeval *tv)
{
    printf("%s { .tv_sec=%ld, .tv_usec=%ld }\n", 
            tag, (long) tv->tv_sec, (long) tv->tv_usec);
}

void evcoap_dbg_print_buffer(const char *id, const ev_uint8_t *b, size_t blen)
{
    size_t i;
    const char *tag = id ? id : "ANONBUF";

    printf("<%s>\n", tag);
    for (i = 0; i < blen; ++i)
    {
        printf("0x%02x", b[i]);
        printf("%s", (i%4 == 3) ? "\n" : " ");
    }

    printf("</%s>\n", tag);
}
