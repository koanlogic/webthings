## TD_COAP_CORE_12
##
## description: Handle request containing several URI-Path options
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
t_dbg "[Step 1] Client is requested to send a confirmable GET request to"\
      "server’s resource."

t_cli_set_type CON
t_cli_set_method GET
t_cli_set_path /seg1/seg2/seg3

out=`t_cli_run`

#
# Step 2
#
t_dbg "[Step 2] Sent request must contain: Type = 0 (CON); Code = 1 (GET);"\
      "Option type = URI-Path (one for each path segment)."

t_field_check 1 srv T CON
t_field_check 1 srv Code GET

# check that we have all 3 URI-Path Options
if [ "${EC_PLUG_DUMP}" = "1" ]; then
    f="1-srv.dump"
    grep "URI-Path: seg1" "${f}" >/dev/null
    [ $? -eq 0 ] || t_die ${EC_PLUG_RC_GENERR} "seg1 not found!"
    grep "URI-Path: seg2" "${f}" >/dev/null
    [ $? -eq 0 ] || t_die ${EC_PLUG_RC_GENERR} "seg2 not found!"
    grep "URI-Path: seg3" "${f}" >/dev/null
    [ $? -eq 0 ] || t_die ${EC_PLUG_RC_GENERR} "seg3 not found!"
fi

#
# Step 3
#
t_dbg "[Step 3] Server sends response containing: Code = 69 (2.05 content);"\
      "Payload = Content of the requested resource; Content type option."

t_field_check 1 cli Code "2.05 (Content)"

# compare hex representations
t_field_check 1 cli Payload `t_str2hex "Hello world!"`

t_field_get 1 cli Content-Type 1>/dev/null
[ $? -ne 1 ] || t_die ${EC_PLUG_RC_GENERR} "field must be defined!"

#
# Step 4
#
t_dbg "[Step 4] Client displays the response."

t_dbg "${out}"
if [ "${EC_PLUG_MODE}" != "srv" ]; then
    t_cmp "${out}" "Hello world!"
fi

#
# Cleanup
#
t_term
