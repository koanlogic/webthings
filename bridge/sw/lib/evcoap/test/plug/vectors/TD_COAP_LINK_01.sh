## TD_COAP_LINK_01
##
## description: Access to well-known interface for resource discovery
## status: complete, tested

. ../share/common.sh

#
# Init
#
t_init
t_srv_run_bg

#
# Step 1
#
t_dbg "[Step 1] Client is requested retrieve Server’s list of resource."

t_cli_set_type CON
t_cli_set_method GET
t_cli_set_path /.well-known/core

out=`t_cli_run`

#
# Step 2
#
t_dbg "[Step 2] Client sends a GET request to Server for"\
      "/.well-known/core resource."

t_field_check 1 srv T CON
t_field_check 1 srv Code GET

#
# Step 3
#
t_dbg "[Step 3] Server sends response containing: Content-Type option"\
      "indicating 40 (application/link-format); payload indicating all"\
      "the links available on Server."

t_field_check 1 cli Code "2.05 (Content)"
t_field_check 1 cli Content-Type "40"   # application/link-format

if [ "${EC_PLUG_MODE}" != "cli" ]; then 
    v=`t_field_get 1 srv MID`
    t_field_check 1 cli MID "${v}"
fi

#
# Step 4
#
t_dbg "[Step 4] Client displays the list of resources available on Server."

t_dbg "${out}"

#
# Cleanup
#
t_term
