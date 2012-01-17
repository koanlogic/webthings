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
        int *flags, struct sockaddr *peer, ev_socklen_t *peer_len, int *e)
{
    ev_ssize_t n;
    struct msghdr msg;
    struct iovec iov[1];

    dbg_return_if (sd == -1, -1);
    dbg_return_if (b == NULL, -1);
    dbg_return_if (e == NULL, -1);
    dbg_return_if (flags == NULL, -1);
    /* b_sz==0 allowed here ? */

    memset(&msg, sizeof msg, 0);

    msg.msg_name = peer;
    msg.msg_namelen = *peer_len;
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

void ec_net_pullup_all(evutil_socket_t sd, ec_pdu_handler_t pdu_proc, void *arg)
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
        if (pdu_proc(d, (size_t) n, sd, &peer, arg))
            continue;
    }
}

int ec_net_send(ev_uint8_t h[4], ev_uint8_t *o, size_t o_sz, ev_uint8_t *p,
        size_t p_sz, evutil_socket_t sd, struct sockaddr_storage *d)
{
    struct msghdr msg;
    size_t iov_idx = 0;
    struct iovec iov[3];

    dbg_return_if (h == NULL, -1);
    dbg_return_if (sd == -1, -1);
    dbg_return_if (d == NULL, -1);

    /* Header is non optional. */
    iov[iov_idx].iov_base = (void *) h;
    iov[iov_idx].iov_len = 4;
    ++iov_idx;

    /* Add options, if any. */
    if (o && o_sz)
    {
        iov[iov_idx].iov_base = (void *) o;
        iov[iov_idx].iov_len = o_sz;
        ++iov_idx;
    }
    
    /* Add payload, if any. */
    if (p && p_sz)
    {
        iov[iov_idx].iov_base = (void *) p;
        iov[iov_idx].iov_len = p_sz;
        ++iov_idx;
    }

    msg.msg_name = (void *) d;
    msg.msg_namelen = d->ss_len;
    msg.msg_iov = iov;
    msg.msg_iovlen = iov_idx;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    dbg_err_sif (sendmsg(sd, &msg, 0) == -1);

    return 0;
err:
    return -1;
}

int ec_net_save_us(ec_conn_t *conn, evutil_socket_t sd)
{
    dbg_return_if (sd == -1, -1);
    dbg_return_if (conn == NULL, -1);

    ev_socklen_t slen = sizeof conn->us;

    dbg_err_sif (getsockname(sd, (struct sockaddr *) &conn->us, &slen) == -1);

    conn->socket = sd;

    return 0;
err:
    return -1;
}

int ec_net_set_confirmable(ec_conn_t *conn, bool is_con)
{
    dbg_return_if (conn == NULL, -1);

    conn->is_confirmable = is_con ? 1 : 2;

    return 0;
}

int ec_net_get_confirmable(ec_conn_t *conn, bool *is_con)
{
    dbg_return_if (conn == NULL, -1);
    dbg_return_if (is_con == NULL, -1);

    switch (conn->is_confirmable)
    {
        case 1:
            *is_con = true;
            break;
        case 2:
            *is_con = false;
            break;
        case 0:
            u_dbg("confirmable flag not set !");
            /* Fall through. */
        default:
            return -1;
    }

    return 0;
}

