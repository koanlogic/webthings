## TD_COAP_CORE_09
##
## description: Perform GET transaction with a separate response
## status: complete, tested

. ../share/common.sh

#
# Init
#
t_init
c="Hello world!"

# server responds after 1 second
t_srv_set_sep 1
t_srv_run_bg

#
# Step 1
#
t_dbg "[Step 1] Client is requested to send a confirmable GET request to"\
      "server’s resource."

t_cli_set_type CON
t_cli_set_method GET
t_cli_set_path /separate

out=`t_cli_run`

#
# Step 2
#
t_dbg "[Step 2] Sent request must contain: Type = 0 (CON); Code = 1 (GET);"\
      "Client generated Message ID."

t_field_check 1 srv T CON
t_field_check 1 srv Code GET

cmid=`t_field_get 1 srv MID`
[ $? -ne 1 ] || t_die ${EC_PLUG_RC_GENERR} "field must be defined!"

#
# Step 3
#
t_dbg "[Step 3] Server sends response containing: Type = 2 (ACK); message ID"\
      "same as the request; empty Payload."

t_field_check 1 cli T ACK
t_field_check 1 cli MID "${cmid}"
t_field_get 1 cli Payload >/dev/null
[ $? -eq 0 ] && t_die ${EC_PLUG_RC_GENERR} "field must be undefined!"

#
# Step 4
#
t_dbg "[Step 4] Server sends response containing: Type = 0 (CON); Code = 69"\
      "(2.05 content); Payload = Content of the requested resource; Content"\
      "type option."

t_field_check 2 cli T CON
t_field_check 2 cli Code "2.05 (Content)"
t_field_check 2 cli Payload `t_str2hex "${c}"`
t_field_get 2 cli Content-Type >/dev/null
[ $? -ne 1 ] || t_die ${EC_PLUG_RC_GENERR} "field must be defined!"
mid=`t_field_get 2 cli MID`

#
# Step 5
#
t_dbg "[Step 5] Client sends response containing: Type = 2 (ACK); message ID"\
      "same as the response; empty Payload."

t_field_check 2 srv T ACK
t_field_check 2 srv MID "${mid}"
t_field_get 2 srv Payload >/dev/null
[ $? -eq 0 ] && t_die ${EC_PLUG_RC_GENERR} "field must be undefined!"

#
# Step 6
#
t_dbg "[Step 6] Client displays the response."

t_dbg "${out}"
if [ "${EC_PLUG_MODE}" != "srv" ]; then
    t_cmp "${out}" "${c}"
fi

#
# Cleanup
#
t_term
