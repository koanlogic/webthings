## TD_COAP_CORE_16
##
## description: Perform GET transaction with a separate response (NON mode)
## status: complete, tested

. ../share/common.sh

#
# Init
#
t_init
c="separate value"

# server responds after 1 second
t_srv_set_sep 1
t_srv_run_bg

#
# Step 1
#
t_dbg "[Step 1] Client is requested to send a confirmable GET request to"\
      "server’s resource."

t_cli_set_type NON
t_cli_set_method GET
t_cli_set_path /separate

out=`t_cli_run`

#
# Step 2
#
t_dbg "[Step 2] Sent request must contain: Type = 1 (NON); Code = 1 (GET);"\
      "Client generated Message ID."

t_field_check 1 srv T NON
t_field_check 1 srv Code GET

cmid=`t_field_get 1 srv MID`
[ $? -eq 1 ] && t_die ${EC_PLUG_RC_GENERR} "field must be defined!"

#
# Step 3
#
t_dbg "[Step 3] Server does *not* send response containing: Type = 2 (ACK);"\
      "message ID same as the request; empty Payload."

t_field_diff 1 cli T ACK
t_field_diff 1 cli MID "${cmid}"
t_field_get 1 cli Payload >/dev/null
[ $? -eq 1 ] && t_die ${EC_PLUG_RC_GENERR} "field must be defined!"

#
# Step 4
#
t_dbg "[Step 4] Server sends response containing: Type = 1 (NON);"\
      "Code = 69 (2.05 content); Payload = Content of the requested resource;"\
      "Content type option."

t_field_check 1 cli T NON
t_field_check 1 cli Code "2.05 (Content)"
t_field_check 1 cli Payload `t_str2hex "${c}"`
t_field_get 1 cli Content-Type >/dev/null
[ $? -eq 1 ] && t_die ${EC_PLUG_RC_GENERR} "field must be defined!"

# Step 5
#
t_dbg "[Step 5] Client displays the response."

t_dbg "${out}"
if [ "${EC_PLUG_MODE}" != "srv" ]; then
    t_cmp "${out}" "${c}"
fi

#
# Cleanup
#
t_term
