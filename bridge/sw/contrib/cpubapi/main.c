#include <u/libu.h>
#include <pubapi.h>

int facility = LOG_LOCAL0;

static void usage(void)
{
    u_con("usage: cpubapi file.conf [attr_name] [attr_val_substr]\n");
    exit(1);
}

static int cb_attr_print(const void *key, const void *val)
{
    u_con("    %s: %s", key, val);
    return 0;
}

static int svc_cb(svc_t *svc, void *arg)
{
    u_uri_t *uri;
    u_hmap_t *attrs;

    u_unused_args(arg);

    dbg_err_if(svc_uri(svc, &uri));
    dbg_err_if(svc_attrs(svc, &attrs));

    u_uri_print(uri, 1);

    dbg_err_if(u_hmap_foreach_keyval(attrs, cb_attr_print));

    u_con("\n");

    return 0;
err:
    return ~0;
}

int main(int argc, char **argv) 
{ 
    pubapi_t *pa = NULL;
    u_config_t *config = NULL;
    time_t last_update = 0;
    const char *config_file;

    if(argc < 2)
        usage();

    config_file = argv[1];

    con_err_ifm(u_config_load_from_file(config_file, &config),
            "can't open the config file: %s", config_file);

    con_err_if(pubapi_connect(config, &pa));

    if(argc == 4)
    {
        con_err_if(pubapi_fetch_services_by_attr(pa, svc_cb, NULL, 
                    argv[2], argv[3]));
    } else if(argc == 3) {
        con_err_if(pubapi_fetch_services_by_attr(pa, svc_cb, NULL, 
                    argv[2], NULL));
    } else
        con_err_if(pubapi_fetch_services(pa, svc_cb, NULL));

    con_err_if(pubapi_last_update(pa, &last_update));

    pubapi_close(pa); pa = NULL;

    return 0; 
err:
    if(pa)
        pubapi_close(pa);
    return 1; 
}

