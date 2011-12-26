#ifndef _DEMO_COAP_Z1_H_
#define _DEMO_COAP_Z1_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "erbium.h"
#include "dev/leds.h"
#include "dev/tmp102.h"
#include "dev/adxl345.h"

#if WITH_COAP == 3
#include "er-coap-03.h"
#elif WITH_COAP == 6
#include "er-coap-06.h"
#elif WITH_COAP == 7
#include "er-coap-07.h"
#else
#warning "REST example without CoAP"
#endif

#define DEBUG 1

#if DEBUG

    #define PRINTF(...) printf(__VA_ARGS__)

    #define PRINT6ADDR(addr) \
        PRINTF("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]", \
                ((u8_t *)addr)[0], ((u8_t *)addr)[1], ((u8_t *)addr)[2],      \
                ((u8_t *)addr)[3], ((u8_t *)addr)[4], ((u8_t *)addr)[5],      \
                ((u8_t *)addr)[6], ((u8_t *)addr)[7], ((u8_t *)addr)[8],      \
                ((u8_t *)addr)[9], ((u8_t *)addr)[10], ((u8_t *)addr)[11],    \
                ((u8_t *)addr)[12], ((u8_t *)addr)[13], ((u8_t *)addr)[14],   \
                ((u8_t *)addr)[15])

    #define PRINTLLADDR(lladdr)                                               \
            PRINTF("[%02x:%02x:%02x:%02x:%02x:%02x]",                         \
                    (lladdr)->addr[0], (lladdr)->addr[1], (lladdr)->addr[2],  \
                    (lladdr)->addr[3],(lladdr)->addr[4], (lladdr)->addr[5])

#else
    #define PRINTF(...)
    #define PRINT6ADDR(addr)

#endif /* DEBUG */

#define ERR_IF(cond)                                    \
    do {                                                \
        if (cond) {                                     \
            PRINTF("[err][%s:%s:%d]\n",                 \
                    __FILE__, __FUNCTION__, __LINE__);  \
            goto err;                                   \
        }                                               \
    } while (0);

#endif
