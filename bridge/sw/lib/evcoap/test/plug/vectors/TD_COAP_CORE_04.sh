## TD_COAP_CORE_03
##
## status: incomplete,tested

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

out=`t_run_cli DELETE CON "" /test`

#
# Step 2
#
t_dbg "# Step 2"

t_check_field 1 srv T CON
t_check_field 1 srv Code DELETE

#
# Step 3
#
t_dbg "# Step 4"

t_check_field 1 cli Code "2.02 (Deleted)"
v=`t_get_field 1 srv MID`
t_check_field 1 cli MID "${v}"

#
# Step 4 TODO
#
t_dbg "# Step 5"

t_dbg "< ${out}"

#
# Cleanup
#
t_term
