## TD_COAP_OBS_05
##
## description: Server detection of deregistration (explicit RST)
## status: incomplete,tested

. ../share/common.sh

#
# Init
#
t_init
t_srv_run_bg

#
# Step 1
#
t_dbg "[Step 1] Client is rebooted."

t_cli_set_type CON
t_cli_set_method GET
t_cli_set_path /obs

# long-running observation
t_cli_set_observe 9999

t_cli_run_bg 1>&2
cpid=$!
t_dbg "client pid: $cpid"

# reboot client 
sleep 1
kill ${cpid} 
t_cli_run_bg 1>&2 
cpid=$!

# TODO should no longer receive
sleep 1

#
# Step 2
#
t_dbg "[Step 2] Server sends response containing Observe option."

echo "# [warn] incomplete!"

#
# Cleanup
#
t_term
