#include <u/libu.h>
#include "evcoap_net.h"

evutil_socket_t ec_net_bind_socket(struct sockaddr_storage *ss, int ss_len)
{
    int sd = -1;
    const struct sockaddr *sa = (const struct sockaddr *) ss;

    dbg_err_sif ((sd = socket(sa->sa_family, SOCK_DGRAM, 0)) == -1);
    dbg_err_sif (bind(sd, sa, ss_len) == -1);

    return sd;
err:
    return -1;
}
