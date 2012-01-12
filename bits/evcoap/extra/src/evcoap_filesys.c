#include "evcoap_filesys.h"

ec_filesys_t *ec_filesys_create(void)
{
    return NULL;
}

void ec_filesys_destroy(ec_filesys_t *fs)
{
    return;
}

int ec_filesys_add_resource(ec_filesys_t *filesys, ec_filesys_res_t *res)
{
    return -1;
}

int ec_filesys_del_resource(ec_filesys_t *filesys, const char *uri)
{
    return -1;
}

ec_filesys_res_t *ec_filesys_new_resource(const char *uri, ev_uint32_t max_age)
{
    return NULL;
}

void ec_filesys_free_resource(ec_filesys_res_t *res)
{
    return;
}

int ec_filesys_add_representation(ec_filesys_res_t *res, const ev_uint8_t *data,
        size_t data_sz, ec_mt_t media_type)
{
    return -1;
}

