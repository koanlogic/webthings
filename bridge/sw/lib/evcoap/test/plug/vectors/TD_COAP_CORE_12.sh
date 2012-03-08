## TD_COAP_CORE_12
##
## description: Handle request containing several URI-Path options
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

out=`t_run_cli GET CON "" /seg1/seg2/seg3`

#
# Step 2
#
t_dbg "# Step 2"

t_check_field 1 srv T CON
t_check_field 1 srv Code GET

# check that we have all 3 URI-Path Options
f="1-srv.dump"
grep "URI-Path: seg1" "${f}" >/dev/null
[ $? -eq 0 ] || t_die 1 "seg1 not found!"
grep "URI-Path: seg2" "${f}" >/dev/null
[ $? -eq 0 ] || t_die 1 "seg2 not found!"
grep "URI-Path: seg3" "${f}" >/dev/null
[ $? -eq 0 ] || t_die 1 "seg3 not found!"

#
# Step 3
#
t_dbg "# Step 3"

t_check_field 1 cli Code "2.05 (Content)"

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
