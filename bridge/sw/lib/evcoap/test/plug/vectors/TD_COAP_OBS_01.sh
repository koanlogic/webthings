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
spid=$!

# terminate test in 2 seconds
t_timer 2 "t_dbg terminating test" "kill ${spid}"

#
# Step 1
#
t_dbg "[Step 1] Client is requested to observe resource /obs on Server."

t_cli_set_type CON
t_cli_set_method GET
t_cli_set_path /obs
t_cli_set_observe 9999
t_cli_run 1>&2 2>/dev/null

# stop server after 2 seconds
t_dbg "waiting for notification..."

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

obs1=`t_field_get 1 cli Observe`
[ $? -ne 1 ] || t_die 1 "field must be defined!"

#
# Step 4
#
t_dbg "[Step 4] Client displays the received information."

#
# Step 5
#
t_dbg "[Step 5] Server sends response containing Observe option indicating"\
      "increasing values, as resource changes."

obs2=`t_field_get 2 cli Observe`
[ $? -ne 1 ] || t_die 1 "field must be defined!"

[ ${obs2} -gt ${obs1} ] || t_die 1 "Observe must have increasing values!"

#
# Step 6 - info already displayed
#
t_dbg "[Step 6] Client displays the updated information."

#
# Cleanup
#
t_term
