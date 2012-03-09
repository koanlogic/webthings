## TD_COAP_CORE_11
##
## description: Handle request not containing Token option
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

# no Token option (= default)
out=`t_run_cli GET CON "" /test`

#
# Step 2
#
t_dbg "# Step 2"

t_check_field 1 srv T CON
t_check_field 1 srv Code GET

# make sure token is undefined
t_get_field 1 srv Token 1>/dev/null
[ $? -eq 0 ] && t_die 1 "field should be undefined!"

#
# Step 3
#
t_dbg "# Step 3"

t_check_field 1 cli Code "2.05 (Content)"

# make sure token is undefined
t_get_field 1 cli Token 1>/dev/null
[ $? -ne 0 ] || t_die 1 "field should be undefined!"

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
