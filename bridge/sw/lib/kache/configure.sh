#!/bin/sh

export makl_conf_h=kache_conf.h

. $MAKL_DIR/cf/makl.init
makl_args_init "$@"

# source command line options' hooks
# --enable_debug
# --enable_warns
. build/mk_enable_debug
. build/mk_enable_warns
. build/mk_enable_extra

makl_pkg_name "kache"
makl_pkg_version "0.1"

makl_args_handle "$@"

# top level source directory 
makl_set_var_mk "SRCDIR" "`pwd`"

#local includes
makl_append_var_mk "CFLAGS" "-I\$(SRCDIR)"
makl_append_var_mk "CFLAGS" "-I\$(SRCDIR)/include"
makl_append_var_mk "CFLAGS" "-DHAVE_CONF_H"

# deps flags
LDIR=`makl_get_var_mk "LIBDIR"`
IDIR=`makl_get_var_mk "INCDIR"`
BDIR=`makl_get_var_mk "BINDIR"`
DDIR=`makl_get_var_mk "DESTDIR"`

# libevent
#makl_add_var_mk "LIBEVENT_LDADD" "${LDIR}/libevent.a"
#makl_add_var_mk "LIBEVENT_CFLAGS" "-I${IDIR}"

# libu
makl_add_var_mk "LIBU_LDADD" "${LDIR}/libu.a"
makl_add_var_mk "LIBU_CFLAGS" "-I${IDIR}"

#install headers in a private subdir
makl_set_var_mk "INCDIR" "${IDIR}/kache"

. $MAKL_DIR/cf/makl.term
