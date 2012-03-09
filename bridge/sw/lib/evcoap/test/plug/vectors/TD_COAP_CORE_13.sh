## TD_COAP_CORE_13
##
## description: Handle request containing several URI-Query options
## status: complete,tested

. ../share/common.sh

#
# Init
#
t_init
t_run_srv

#
# Step 1
#
t_dbg "# Step 1"

params="first=1&second=2&third=3"
out=`t_run_cli GET CON "" "/query?${params}"`

#
# Step 2
#
t_dbg "# Step 2"

t_check_field 1 srv T CON
t_check_field 1 srv Code GET
t_check_field 1 srv URI-Query "${params}"

#
# Step 3
#
t_dbg "# Step 3"

t_check_field 1 cli Code "2.05 (Content)"

# compare hex representations
t_check_field 1 cli Payload `t_str2hex "Hello world!"`

t_get_field 1 cli Content-Type 1>/dev/null
[ $? -ne 1 ] || t_die 1 "field should be defined!"

#
# Step 4
#
t_dbg "# Step 4"

t_dbg "${out}"
if [ "${MODE}" != "srv" ]; then
    t_cmp "${out}" "Hello world!"
fi

#
# Cleanup
#
t_term
