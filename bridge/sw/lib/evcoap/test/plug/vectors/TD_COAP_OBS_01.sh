## TD_COAP_OBS_01
##
## description: Handle resource observation
## status: complete,tested

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
t_cli_set_path /obs
t_cli_set_observe 9999

# kill processes after 2 seconds
t_dbg "# waiting for notification..."
t_timer 2

t_cli_run 1>&2

#
# Step 2
#
t_dbg "# Step 2"

t_field_check 1 srv Code GET
t_field_check 1 srv Observe 0

#
# Step 3
#
t_dbg "# Step 3"

obs1=`t_field_get 1 cli Observe`
[ $? -ne 1 ] || t_die 1 "field must be defined!"

#
# Step 4 - info already displayed
#
#t_dbg "# Step 4"

#
# Step 5
#
t_dbg "# Step 5"

obs2=`t_field_get 2 cli Observe`
[ $? -ne 1 ] || t_die 1 "field must be defined!"

[ ${obs2} -gt ${obs1} ] || t_die 1 "Observe must have increasing values!"

#
# Step 6 - info already displayed
#
#t_dbg "# Step 6"

#
# Cleanup
#
t_term
