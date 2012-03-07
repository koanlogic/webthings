. ../share/common.sh

t_init

t_run_srv

#
# Step 1
#
out=`t_run_cli POST CON "" /test`
t_dbg "< ${out}"

#
# Step 2
#
t_check_hdr 1 srv T CON
t_check_hdr 1 srv Code POST

#
# Step 3
#
t_check_hdr 1 cli Code "2.01 (Created)"
v=`t_get_hdr 1 srv MID`
t_check_hdr 1 cli MID "${v}"

#
# Step 4 TODO
#

t_term
