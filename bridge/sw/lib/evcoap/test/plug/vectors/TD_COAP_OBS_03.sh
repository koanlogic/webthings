## TD_COAP_OBS_03
##
## description: Client detection of deregistration (Max-Age)
## status: incomplete,tested

. ../share/common.sh

#
# Init
#
t_init
t_srv_run
spid=$!
t_dbg "server pid: $spid"

#
# Step 1
#
t_dbg "[Step 1] Server is rebooted."

t_cli_set_type CON
t_cli_set_method GET
t_cli_set_path /obs

# long-running observation
t_cli_set_observe 9999

t_cli_run 1>&2 2>/dev/null

# reboot the server after a few seconds
sleep 2 
kill ${spid} 
t_srv_run

#
# Step 2
#
t_dbg "[Step 2] Server does not send notifications."

# server does not send notifications
t_field_get 3 cli Code >/dev/null
[ $? -eq 0 ] && t_die 1 "no further notifications should exist!"

#
# Step 3
#
t_dbg "[Step 3] Client does not display updated information."

#
# Step 4
#
t_dbg "[Step 4] After Max-Age expiration, Client sends a new GET with Observe"\
      "option for Server's observable resource."

echo "# [warn] incomplete!!"

sleep 2
#t_cli_set_observe 2
#t_cli_run 1>&2

#
# Step 5
#
#t_dbg "[Step 5] Sent request contains Observe option indicating 0."

#
# Step 6
#
#t_dbg "[Step 6] Server sends response containing Observe option."

#
# Step 7
#
#t_dbg "[Step 7] Client displays the received information."

#
# Step 8
#
#t_dbg "[Step 8] Server sends response containing Observe option indicating"
#increasing values, as resource changes."

#
# Step 9
#
#t_dbg "[Step 9] Client displays the updated information."

#
# Cleanup
#
t_term
