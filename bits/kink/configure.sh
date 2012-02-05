#!/bin/sh

export makl_conf_h="kink_conf.h"

. "${MAKL_DIR}"/cf/makl.init
makl_args_init "$@"

# source command line options' hooks
# --enable_debug
# --enable_warns
. build/mk_enable_debug
. build/mk_enable_warns

makl_pkg_name "kink"
makl_pkg_version

# top level source directory 
makl_set_var_mk "SRCDIR" "`pwd`"

target="`makl_target_name`"
case ${target} in
    *darwin*)
        makl_set_var "OS_DARWIN"
        makl_set_var "PRE_LDADD" "-ldl"
        ;;
    *linux*)
        makl_set_var "OS_LINUX"
        makl_append_var_mk "LDADD" "-lrt"
        ;;
esac

# local include path
makl_append_var_mk "CFLAGS" "-I\$(SRCDIR)"
makl_append_var_mk "CFLAGS" "-DHAVE_CONF_H"

# kink requires libevent and libu (and TODO evcoap)
makl_require lib event
makl_require lib u

makl_args_handle "$@"

. "${MAKL_DIR}"/cf/makl.term
