## TD_COAP_OBS_02
##
## description: Stop resource observation
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
t_dbg "[Step 1] Client is requested to stop observing resource /obs on Server."

t_cli_set_type CON
t_cli_set_method GET
t_cli_set_path /obs

# when counter expires, client sends GET request not containing Observe option
t_cli_set_observe 2

t_cli_run 1>&2

#
# Step 2
#
t_dbg "[Step 2] Client sends GET request not containing Observe option."

# unset observe field and make a new request
t_cli_set_observe
t_cli_run 1>&2

t_field_get 3 srv Observe >/dev/null
[ $? -eq 0 ] && t_die 1 "field must be undefined!"

#
# Step 3
#
t_dbg "[Step 3] Server sends response not containing Observe option."

# second message from server (stopping)
t_field_get 3 cli Observe >/dev/null
[ $? -eq 0 ] && t_die 1 "field must be undefined!"

#
# Step 4
#
t_dbg "[Step 4] Client displays the received information."

#
# Step 5
#
t_dbg "[Step 5] Server does not send further response."

# futher messages must not exist
t_field_get 3 cli Code >/dev/null
[ $? -eq 0 ] && t_die 1 "no messages should exist!"

#
# Step 6 - info already (not) displayed
#
t_dbg "[Step 6] Client does not display updated information."

#
# Cleanup
#
t_term
