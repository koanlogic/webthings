## TD_COAP_OBS_05
##
## description: Server detection of deregistration (explicit RST)
## status: incomplete,tested

. ../share/common.sh

#
# Init
#
t_init
t_srv_run

#
# Step 1
#
t_dbg "[Step 1] Client is rebooted."

t_cli_set_type CON
t_cli_set_method GET
t_cli_set_path /obs

# long-running observation
t_cli_set_observe 9999

t_cli_run 1>&2 2>/dev/null
cpid=$!
t_dbg "client pid: $cpid"

# kill the client after a few seconds
sleep 2
kill ${cpid} 
t_cli_run 1>&2 

sleep 3

#
# Step 2
#
t_dbg "[Step 2] Server sends response containing Observe option."

echo "# [warn] incomplete!"

#
# Cleanup
#
t_term
