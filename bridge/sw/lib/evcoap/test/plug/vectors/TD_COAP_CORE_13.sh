## TD_COAP_CORE_13
##
## description: Handle request containing several URI-Query options
## status: complete,tested

. ../share/common.sh

#
# Init
#
t_init
t_srv_run

#
# Step 1
#
t_dbg "# Step 1"

t_cli_set_type CON
t_cli_set_method GET

params="first=1&second=2&third=3"
t_cli_set_path "/query?${params}"

out=`t_cli_run`

#
# Step 2
#
t_dbg "# Step 2"

t_field_check 1 srv T CON
t_field_check 1 srv Code GET
t_field_check 1 srv URI-Query "${params}"

#
# Step 3
#
t_dbg "# Step 3"

t_field_check 1 cli Code "2.05 (Content)"

# compare hex representations
t_field_check 1 cli Payload `t_str2hex "Hello world!"`

t_field_get 1 cli Content-Type 1>/dev/null
[ $? -ne 1 ] || t_die 1 "field must be defined!"

#
# Step 4
#
t_dbg "# Step 4"

t_dbg "${out}"
if [ "${EC_PLUG_MODE}" != "srv" ]; then
    t_cmp "${out}" "Hello world!"
fi

#
# Cleanup
#
t_term
