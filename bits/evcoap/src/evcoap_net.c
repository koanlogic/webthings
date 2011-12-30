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

ev_ssize_t ec_net_pullup(evutil_socket_t sd, ev_uint8_t *b, size_t b_sz,
        int *flags, struct sockaddr *peer, ev_socklen_t *peerlen, int *e)
{
    ev_ssize_t n;
    struct msghdr msg;
    struct iovec iov[1];

    memset(&msg, sizeof msg, 0);

    msg.msg_name = peer;
    msg.msg_namelen = *peerlen;
    iov[0].iov_base = b;
    iov[0].iov_len = b_sz;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    *e = 0;

    if ((n = recvmsg(sd, &msg, *flags)) < 0)
    {
        if ((*e = evutil_socket_geterror(sd)) != EAGAIN)
            u_warn("%s", evutil_socket_error_to_string(*e));
     
        goto err;
    }

    *flags = msg.msg_flags;

    /* TODO retrieve cmsg with type IP_RECVDSTADDR to tell datagrams that 
       where sent to a multicast destination. */

    return n;
err:
    return -1;
}

void ec_net_dispatch(evutil_socket_t sd, ec_pdu_handler_t pdu_proc, void *arg)
{
    int e;
    struct sockaddr_storage peer;
    ev_socklen_t peer_len = sizeof(peer);
    ev_uint8_t d[EC_COAP_MAX_REQ_SIZE + 1];

    /* Dequeue all buffered PDUs. */
    for (;;)
    {
        int flags = 0;

        /* Pull up next UDP packet from the socket input buffer. */
        ev_ssize_t n = ec_net_pullup(sd, d, sizeof d, &flags,
                (struct sockaddr *) &peer, &peer_len, &e);

        /* Skip empty or too big UDP datagrams (TODO check truncation.) */
        if (!n || n == sizeof d)
            continue;

        if (n < 0)
        {
            /* If no messages are available at the socket, the receive call
             * waits for a message to arrive, unless the socket is nonblocking 
             * in which case the value -1 is returned and the external variable
             * errno set to EAGAIN. */
            switch (e)
            {
                case EAGAIN:
                    return;
                case EINTR:
                    continue;
                default:
                    u_warn("%s", evutil_socket_error_to_string(e));
                    return;
            }
        }

        /* Process the received PDU invoking whatever PDU processor was 
         * supplied (i.e. client or server.) */
        if (pdu_proc(d, (size_t) n, arg))
            continue;
    }
}

