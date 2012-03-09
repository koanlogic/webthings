## TD_COAP_CORE_02
##
## description: Perform POST transaction (CON mode)
## status: complete,tested

. ../share/common.sh

#
# Init
#
t_init
t_srv_run

#
# Step 1
#
t_dbg "# Step 1"

# prepare arbitrary payload
pf=.`basename $0`.payload
p="lots of cool stuff"
${ECHO} -n "${p}" > ${pf}

t_cli_set_type CON
t_cli_set_method POST
t_cli_set_payload ${pf}

out=`t_cli_run`

t_field_get 1 srv Content-Type 1>/dev/null
[ $? -ne 1 ] || t_die 1 "field should be defined!"

#
# Step 2
#
t_dbg "# Step 2"

t_field_check 1 srv T CON
t_field_check 1 srv Code POST

#
# Step 3
#
t_dbg "# Step 3"

# compare hex representations
t_field_check 1 srv Payload `t_str2hex ${p}`

#
# Step 4
#
t_dbg "# Step 4"

t_field_check 1 cli Code "2.01 (Created)"
v=`t_field_get 1 srv MID`
t_field_check 1 cli MID "${v}"

#
# Step 5
#
t_dbg "# Step 5"

t_dbg "${out}"
if [ "${EC_PLUG_MODE}" != "srv" ]; then
    t_cmp "${out}" "Hello world!"
fi

#
# Cleanup
#
rm -f ${pf}
t_term
