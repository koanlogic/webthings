#!/bin/sh

export makl_conf_h=evcoap_conf.h

. "${MAKL_DIR}"/cf/makl.init
makl_args_init "$@"

# source command line options' hooks
. build/mk_enable_debug
. build/mk_enable_warns

makl_pkg_name "evcoap"
makl_pkg_version

# top level source directory 
makl_set_var_mk "SRCDIR" "`pwd`"

target="`makl_target_name`"
case ${target} in
    *linux*)
        makl_set_var "OS_LINUX"
        ;;
    *darwin*)
        makl_set_var "OS_DARWIN"
        # workaround to avoid circular dependecy error on Mac OS X 
        makl_set_var "PRE_LDADD" "-ldl"
        ;;
    *)
        makl_err "unsupported platform"
        ;;
esac

# local and include's
makl_append_var_mk "CFLAGS" "-I\$(SRCDIR) -I\$(SRCDIR)/include -DHAVE_CONF_H"

# evcoap requires libevent and libu
makl_require lib event
makl_require lib u

makl_args_handle "$@"

# install headers in a private subdir
makl_set_var_mk "INCDIR" "${IDIR}/evcoap"

. "${MAKL_DIR}"/cf/makl.term
