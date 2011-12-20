#include <event2/util.h>
#include <u/libu.h>
#include "evcoap_txn.h"

#define EMPTY_STRING(s)  ((s) == NULL || *(s) == '\0')

int ec_client_set_method(ec_client_t *cli, ec_method_t m)
{
    ec_txn_t *meta = &cli->meta;

    dbg_return_if (m < EC_GET || m > EC_DELETE, -1);

    meta->method = m;

    return 0;
}

int ec_client_set_proxy(ec_client_t *cli, const char *proxy_host,
        ev_uint16_t proxy_port)
{
    ec_conn_t *conn = &cli->meta.conn;

    dbg_return_if (EMPTY_STRING(proxy_host), -1);

    if (proxy_port == 0)
        proxy_port = EC_DEFAULT_PORT;

    dbg_err_if (u_snprintf(conn->proxy_addr, sizeof conn->proxy_addr,
                "%s:%u", proxy_host, proxy_port));

    conn->use_proxy = 1;

    return 0;
err:
    return -1;
}

int ec_client_set_uri(ec_client_t *cli, const char *uri)
{
    ec_conn_t *conn = &cli->meta.conn;
    u_uri_t *u = NULL;
    const char *scheme, *auth;

    /* Parse URI. */
    dbg_err_if (u_uri_crumble(uri, 0, &u));

    /* Do minimal URI validation: expect non empty scheme and authority,
     * at least. */
    dbg_err_if ((scheme = u_uri_get_scheme(u)) == NULL || *scheme == '\0');
    dbg_err_if ((auth = u_uri_get_authority(u)) == NULL || *auth == '\0');

    /* Expect scheme==coap for any non proxy request. */
    dbg_err_ifm (!conn->use_proxy && strcasecmp(scheme, "coap"),
            "expect URI with coap scheme when doing non-proxy requests");

    return 0;
err:
    return -1;
}

void ec_client_free(ec_client_t *cli)
{
    if (cli)
    {
        ec_txn_t *meta = &cli->meta;
        ec_conn_t *conn = &meta->conn;

        /* Close socket. */
        evutil_closesocket(conn->sd);

        /* Free URI. */
        u_uri_free(meta->uri);

        /* TODO free cli->req */
        /* TODO free cli->res */
        /* TODO Destroy any associated timer ? */

        u_free(cli);
    }

    return;
}

ec_client_t *ec_client_new(ec_method_t m, const char *uri,
        const char *proxy_host, ev_uint16_t proxy_port)
{
    ec_client_t *cli = NULL;

    dbg_err_sif ((cli = u_zalloc(sizeof *cli)) == NULL);

    /* Must be done first because the following URI validation also
     * depends on the fact that this request is expected to go through
     * a proxy or not. */
    if (proxy_host)
        dbg_err_if (ec_client_set_proxy(cli, proxy_host, proxy_port));

    dbg_err_if (ec_client_set_method(cli, m));
    dbg_err_if (ec_client_set_uri(cli, uri));

    return cli;
err:
    if (cli)
        ec_client_free(cli);
    return NULL;
}


