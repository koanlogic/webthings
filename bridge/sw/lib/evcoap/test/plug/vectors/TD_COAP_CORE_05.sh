## TD_COAP_CORE_05
##
## description: Perform GET transaction (NON mode)
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

out=`t_run_cli GET NON "" /test`

#
# Step 2
#
t_dbg "# Step 2"

t_check_field 1 srv T NON
t_check_field 1 srv Code GET

#
# Step 3
#
t_dbg "# Step 3"

t_check_field 1 cli T NON
t_check_field 1 cli Code "2.05 (Content)"
v=`t_get_field 1 srv MID`
t_diff_field 1 cli MID "${v}"

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
