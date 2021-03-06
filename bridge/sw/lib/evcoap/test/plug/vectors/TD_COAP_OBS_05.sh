## TD_COAP_OBS_05
##
## description: Server detection of deregistration (explicit RST)
## status: complete,tested
##
## note: needs to be run manually when testing external client/server

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

if [ "${EC_PLUG_MODE}" != "srv" ]; then
    cpid=$!
    t_dbg "client pid: $cpid"

    sleep 1

    # reboot client by sending it a SIGHUP
    t_dbg "rebooting"
    kill -HUP ${cpid} 
fi

sleep 2

#
# Step 2
#
t_dbg "[Step 2] Server sends response containing Observe option."

t_field_get 1 cli Observe >/dev/null
[ $? -ne 1 ] || t_die ${EC_PLUG_RC_GENERR} "field must be defined!"
t_field_get 2 cli Observe >/dev/null
[ $? -ne 1 ] || t_die ${EC_PLUG_RC_GENERR} "field must be defined!"

#
# Step 3
#
t_dbg "[Step 3] Client discards response and does not display information."

#
# Step 4
#
t_dbg "[Step 4] Client sends RST to Server."

t_field_check 2 srv T RST 

#
# Step 5
#
t_dbg "[Step 5] Server does not send further response."

t_field_get 5 cli Observe >/dev/null
[ $? -eq 0 ] && t_die ${EC_PLUG_RC_GENERR} "field must be undefined!"

#
# Cleanup
#
t_term
