## TD_COAP_CORE_01
##
## description: Perform GET transaction (CON mode)
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

out=`t_run_cli GET CON "" /test`

#
# Step 2
#
t_dbg "# Step 2"

t_check_field 1 srv T CON
t_check_field 1 srv Code GET

#
# Step 3
#
t_dbg "# Step 3"

t_check_field 1 cli Code "2.05 (Content)"
v=`t_get_field 1 srv MID`
t_check_field 1 cli MID "${v}"

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
