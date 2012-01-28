#!/bin/sh

export makl_conf_h="include/evcoap_conf.h"

. "${MAKL_DIR}"/cf/makl.init
. build/makl_endiannes
makl_args_init "$@"

# source command line options' hooks
# --enable_debug
# --enable_warns
. build/mk_enable_debug
. build/mk_enable_warns
. build/mk_enable_extra

makl_pkg_name "evcoap"
makl_pkg_version

# top level source directory 
makl_set_var_mk "SRCDIR" "`pwd`"

target="`makl_target_name`"
case ${target} in
    *darwin*)
        makl_set_var "OS_DARWIN"
        # workaround to avoid circular dependecy error on Mac OS X 
        makl_set_var "PRE_LDADD" "-ldl"
        ;;
    *linux*)
        makl_set_var "OS_LINUX"
        makl_append_var_mk "LDADD" "-lrt"
        ;;
esac

# local include path
makl_append_var_mk "CFLAGS" "-I\$(SRCDIR)"
makl_append_var_mk "CFLAGS" "-I\$(SRCDIR)/include"
makl_append_var_mk "CFLAGS" "-I\$(SRCDIR)/extra/include"
makl_append_var_mk "CFLAGS" "-DHAVE_CONF_H"

# evcoap requires libevent and libu
makl_require lib event
makl_require lib u

# Check endiannes of the host machine
makl_endiannes

makl_args_handle "$@"

# install headers in a private subdir
makl_set_var_mk "INCDIR" "${IDIR}/evcoap"

. "${MAKL_DIR}"/cf/makl.term
