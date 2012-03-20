## TD_COAP_CORE_13
##
## description: Handle request containing several URI-Query options
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
t_dbg "[Step 1] Client is requested to send a confirmable GET request with"\
      "three Query parameters (e.g. ?first=1&second=2&third=3) to the"\
      "server’s resource."

t_cli_set_type CON
t_cli_set_method GET

params="first=1&second=2&third=3"
t_cli_set_path "/query?${params}"

out=`t_cli_run`

#
# Step 2
#
t_dbg "[Step 2] Sent request must contain: Type = 0 (CON); Code = 1 (GET);"\
      "Option type = URI-Query (More than one query parameter)."

t_field_check 1 srv T CON
t_field_check 1 srv Code GET
t_field_check 1 srv URI-Query "${params}"

#
# Step 3
#
t_dbg "[Step 3] Server sends response containing: Type = 0/2 (CON/ACK);"\
      "Code = 69 (2.05 content); Payload = Content of the requested resource;"\
      "Content type option."

t_field_check 1 cli Code "2.05 (Content)"

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
