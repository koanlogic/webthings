## TD_COAP_CORE_16
##
## description: Perform GET transaction with a separate response (NON mode)
## status: complete, tested

. ../share/common.sh

#
# Init
#
t_init
c="Hello world!"

# server responds after 1 second
t_srv_set_sep 1
t_srv_run

#
# Step 1
#
t_dbg "# Step 1"

t_cli_set_type NON
t_cli_set_method GET
t_cli_set_path /separate

out=`t_cli_run`

#
# Step 2
#
t_dbg "# Step 2"

t_field_check 1 srv T NON
t_field_check 1 srv Code GET

cmid=`t_field_get 1 srv MID`
[ $? -eq 1 ] && t_die 1 "field must be defined!"

#
# Step 3
#
t_dbg "# Step 3"

t_field_diff 1 cli T ACK
t_field_diff 1 cli MID "${cmid}"
t_field_get 1 cli Payload >/dev/null
[ $? -eq 1 ] && t_die 1 "field must be defined!"

#
# Step 4
#
t_dbg "# Step 4"

t_field_check 1 cli T NON
t_field_check 1 cli Code "2.05 (Content)"
t_field_check 1 cli Payload `t_str2hex "${c}"`
t_field_get 1 cli Content-Type >/dev/null
[ $? -eq 1 ] && t_die 1 "field must be defined!"

# Step 5
#
t_dbg "# Step 5"

t_dbg "${out}"
if [ "${EC_PLUG_MODE}" != "srv" ]; then
    t_cmp "${out}" "${c}"
fi

#
# Cleanup
#
t_term
