## TD_COAP_CORE_07
##
## description: Perform PUT transaction (NON mode)
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

# prepare arbitrary payload
pf=.`basename $0`.payload
p="lots of cool stuff"
${ECHO} -n "${p}" > ${pf}

out=`t_run_cli PUT NON "" /test ${pf}`

#
# Step 2
#
t_dbg "# Step 2"

t_check_field 1 srv T NON
t_check_field 1 srv Code PUT

t_get_field 1 srv Content-Type 1>/dev/null
[ $? -ne 1 ] || t_die 1 "field should be defined!"

#
# Step 3
#
t_dbg "# Step 3"

# compare hex representations
t_check_field 1 srv Payload `t_str2hex ${p}`

#
# Step 4
#
t_dbg "# Step 4"

t_check_field 1 cli T NON
t_check_field 1 cli Code "2.04 (Changed)"
v=`t_get_field 1 srv MID`
t_diff_field 1 cli MID "${v}"

#
# Step 5
#
t_dbg "# Step 5"

t_dbg "${out}"
if [ "${MODE}" != "srv" ]; then
    t_cmp "${out}" "Hello world!"
fi

#
# Cleanup
#
rm -f ${pf}
t_term
