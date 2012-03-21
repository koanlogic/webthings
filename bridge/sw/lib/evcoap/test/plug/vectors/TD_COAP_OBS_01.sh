## TD_COAP_OBS_01
##
## description: Handle resource observation
## status: complete,tested

. ../share/common.sh

#
# Init
#
t_init
t_srv_run_bg

#
# Step 1
#
t_dbg "[Step 1] Client is requested to observe resource /obs on Server."

t_cli_set_type CON
t_cli_set_method GET
t_cli_set_path /obs
t_cli_set_observe 9999
t_cli_run_bg 1>&2
sleep 1

#
# Step 2
#
t_dbg "[Step 2] Client sends a GET request containing Observe option"\
      "indicating 0."

t_field_check 1 srv Code GET
t_field_check 1 srv Observe 0

#
# Step 3
#
t_dbg "[Step 3] Server sends response containing Observe option."

obs1=`t_field_get 2 cli Observe`
[ $? -ne 1 ] || t_die ${EC_PLUG_RC_GENERR} "field must be defined!"

#
# Step 4
#
t_dbg "[Step 4] Client displays the received information."

#
# Step 5
#
t_dbg "[Step 5] Server sends response containing Observe option indicating"\
      "increasing values, as resource changes."

obs2=`t_field_get 3 cli Observe`
[ $? -ne 1 ] || t_die ${EC_PLUG_RC_GENERR} "field must be defined!"

[ ${obs2} -gt ${obs1} ] || t_die ${EC_PLUG_RC_GENERR} "Observe must have increasing values!"

#
# Step 6 - info already displayed
#
t_dbg "[Step 6] Client displays the updated information."

#
# Cleanup
#
t_term
