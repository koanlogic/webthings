## TD_COAP_OBS_04
##
## description: Server detection of deregistration (client OFF)
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
t_dbg "[Step 1] Client is switched off."

t_cli_set_type CON
t_cli_set_method GET
t_cli_set_path /obs

# long-running observation
t_cli_set_observe 9999

t_cli_run_bg 1>&2 2>/dev/null
cpid=$!
t_dbg "client pid: $cpid"

# kill the client after a few seconds
sleep 2
kill ${cpid}

t_die ${EC_PLUG_RC_UNIMPLEMENTED} "CON notifications unimplemented!"

#
# Step 2
#
t_dbg "[Step 2] Server’s confirmable responses are not acknowledged."

#
# Step 3
#
t_dbg "[Step 3] After some delay, Server does not send further responses."

#
# Cleanup
#
t_term
