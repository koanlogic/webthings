## TD_COAP_LINK_01
##
## description: Access to well-known interface for resource discovery
## status: complete, tested

. ../share/common.sh

#
# Init
#
t_init
t_srv_run

#
# Step 1
#
t_dbg "# Step 1"

t_cli_set_type CON
t_cli_set_method GET
t_cli_set_path /.well-known/core

out=`t_cli_run`

#
# Step 2
#
t_dbg "# Step 2"

t_field_check 1 srv T CON
t_field_check 1 srv Code GET
#t_field_check 1 srv URI-Path .well-known/core      # FIXME

#
# Step 3
#
t_dbg "# Step 3"

t_field_check 1 cli Code "2.05 (Content)"
v=`t_field_get 1 srv MID`
t_field_check 1 cli MID "${v}"
t_field_check 1 cli Content-Type "40"   # application/link-format

#
# Step 4
#
t_dbg "# Step 4"

t_dbg "${out}"

#
# Cleanup
#
t_term
