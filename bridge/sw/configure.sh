#!/bin/sh

export makl_conf_h="kink_conf.h"

. "${MAKL_DIR}"/cf/makl.init
makl_args_init "$@"

. build/makl_endiannes
. build/mk_enable_debug
. build/mk_enable_warns
. build/mk_enable_extra
. build/mk_enable_plug

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
makl_append_var_mk "CFLAGS" "-I\$(SRCDIR)/include"
makl_append_var_mk "CFLAGS" "-DHAVE_CONF_H"

# #define features
if [ "`makl_get_var_h "OS_LINUX"`" ]
then
    makl_append_var_mk "CFLAGS" "-D_POSIX_SOURCE"
    makl_append_var_mk "CFLAGS" "-D_BSD_SOURCE"
fi

# hard requirement on libevent and libu
makl_require lib event
makl_require lib u "" "-lm"    # link to math for isfinite()

# Check endiannes of the host machine
makl_endiannes

makl_args_handle "$@"

# install headers in a private subdir
makl_set_var_mk "INCDIR" "${IDIR}/kink"

. "${MAKL_DIR}"/cf/makl.term
