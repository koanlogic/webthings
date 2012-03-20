## TD_COAP_CORE_11
##
## description: Handle request not containing Token option
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
      "server’s resource not containg Token option."

t_cli_set_type CON
t_cli_set_method GET
# no Token option (= default)

out=`t_cli_run`

#
# Step 2
#
t_dbg "[Step 2] Sent request must contain: Type = 0 (CON); Code = 1 (GET);"\
      "No Token option."

t_field_check 1 srv T CON
t_field_check 1 srv Code GET

# make sure token is undefined
t_field_get 1 srv Token 1>/dev/null
[ $? -eq 0 ] && t_die 1 "field must be undefined!"

#
# Step 3
#
t_dbg "[Step 3] Server sends response containing: Code = 69 (2.05 content);"\
      "No Token option; Payload = Content of the requested resource; Content"\
      "type option."

t_field_check 1 cli Code "2.05 (Content)"

# make sure token is undefined
t_field_get 1 cli Token 1>/dev/null
[ $? -ne 0 ] || t_die 1 "field must be undefined!"

# compare hex representations
t_field_check 1 cli Payload `t_str2hex "Hello world!"`

t_field_get 1 cli Content-Type 1>/dev/null
[ $? -ne 1 ] || t_die 1 "field must be defined!"

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
