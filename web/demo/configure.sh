#!/bin/sh

export makl_conf_h="wtdemo_conf.h"

. "${MAKL_DIR}"/cf/makl.init
makl_args_init "$@"

# source-in options' hooks
. build/mk_enable_debug
. build/mk_enable_warns

# wtdemo-x.y.z
makl_pkg_name "wtdemo"
makl_pkg_version

target=`makl_target_name`
case ${target} in
    *darwin*)
        makl_set_var "OS_DARWIN"
        ;;
    *linux*)
        makl_set_var "OS_LINUX"
        ;;
esac

# set default prefix to "./local", override via --prefix=...
makl_set "__prefix__" "`pwd`/local"

makl_set_var_mk "SRCDIR" "`pwd`"

makl_add_var_mk "CFLAGS" "-I\$(SRCDIR)"

# log facility
makl_set_var "LF_WTDEMO" "LOG_LOCAL0"

# -fstack-protector-all (needs gcc >= 4)
# makl_append_var_mk "CFLAGS" "-fstack-protector-all"

# use C99
makl_append_var_mk "CFLAGS" "-std=c99"

makl_args_handle "$@"

# deps flags - none yet
#DD=`makl_get_var_mk "DESTDIR"`
#makl_add_var_mk "LIBCURL_CFLAGS" "-I${DD}/include"
#makl_add_var_mk "LIBCURL_LDADD" "${DD}/lib/libu.a"

makl_file_sub "kloned/webapp/etc/kloned.conf"

. "${MAKL_DIR}"/cf/makl.term
