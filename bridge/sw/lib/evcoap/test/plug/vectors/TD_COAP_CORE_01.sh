. ../share/common.sh

t_init

t_run_srv

#
# Step 1
#
out=`t_run_cli GET CON "" /test`
t_dbg "< ${out}"

#
# Step 2
#
t_check_hdr 1 srv T CON
t_check_hdr 1 srv Code GET

#
# Step 3
#
t_check_hdr 1 cli Code "2.05 (Content)"
v=`t_get_hdr 1 srv MID`
t_check_hdr 1 cli MID "${v}"

#
# Step 4
#
if [ "${MODE}" != "srv" ]; then
    t_cmp "${out}" "Hello world!"
fi

t_term
