## TD_COAP_OBS_03
##
## description: Client detection of deregistration (Max-Age)
## status: incomplete,tested
##
## note: needs to be run manually when testing external client/server

. ../share/common.sh

#
# Init
#
t_init
t_srv_run_bg
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

# reboot the server after a little while
if [ "${EC_PLUG_MODE}" != "cli" ]; then
    t_timer 2 "t_dbg rebooting server" "kill ${spid}" "t_srv_run_bg"
fi

t_cli_run_bg 1>&2 2>/dev/null

#
# Step 2
#
t_dbg "[Step 2] Server does not send notifications."

# server does not send notifications
t_field_get 3 cli Code >/dev/null
[ $? -eq 0 ] && t_die ${EC_PLUG_RC_GENERR} "no further notifications should exist!"

#
# Step 3
#
t_dbg "[Step 3] Client does not display updated information."

#
# Step 4
#
t_dbg "[Step 4] After Max-Age expiration, Client sends a new GET with Observe"\
      "option for Server's observable resource."

t_field_check 1 srv Code GET
mid1=`t_field_get 1 srv MID` 

# wait for kill
sleep 2

t_field_check 1 srv Code GET
mid2=`t_field_get 1 srv MID` 

if [ "${EC_PLUG_DUMP}" = "1" ]; then
    
    # don't do this check unless we are testing our own implementation locally
    # otherwise test should be run manually to get timing right
    if [ "${EC_PLUG_MODE}" = "" ]; then 
        # after rebooting the server, id is reset back to 1 so make sure
        # message is different
        [ "${mid1}" = "${mid2}" ] && t_die ${EC_PLUG_RC_GENERR} \
                "message ID must be different!"
    fi
fi

#
# Step 5
#
t_dbg "[Step 5] Sent request contains Observe option indicating 0."

t_field_check 1 srv Observe 0

#
# Step 6
#
t_dbg "[Step 6] Server sends response containing Observe option."

obs1=`t_field_get 2 cli Observe`
[ $? -ne 1 ] || t_die ${EC_PLUG_RC_GENERR} "field must be defined!"

#
# Step 7
#
t_dbg "[Step 7] Client displays the received information."

#
# Step 8
#
t_dbg "[Step 8] Server sends response containing Observe option indicating"\
      "increasing values, as resource changes."

obs2=`t_field_get 3 cli Observe`
[ $? -ne 1 ] || t_die ${EC_PLUG_RC_GENERR} "field must be defined!"

[ ${obs2} -gt ${obs1} ] || t_die ${EC_PLUG_RC_GENERR} "Observe must have increasing values!"

#
# Step 9
#
t_dbg "[Step 9] Client displays the updated information."

#
# Cleanup
#
t_term
