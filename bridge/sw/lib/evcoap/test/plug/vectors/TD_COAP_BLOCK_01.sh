## TD_COAP_BLOCK_01
##
## description: Handle GET blockwise transfer for large resource (early negotiation)
## status: incomplete,untested

. ../share/common.sh

t_die 1 "# Unimplemented!"

#
# Init
#
t_init
t_srv_run

#
# Step 1
#
t_dbg "# Step 1"

out=`t_cli_run GET CON "" /large`

t_term
exit 0

#
# Step 2
#
t_dbg "# Step 2"

t_field_check 1 srv T CON
t_field_check 1 srv Code GET

#
# Step 3
#
t_dbg "# Step 3"

t_field_check 1 cli Code "2.05 (Content)"
v=`t_field_get 1 srv MID`
t_field_check 1 cli MID "${v}"

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

