## TD_COAP_CORE_03
##
## description: Perform PUT transaction (CON mode)
## status: complete,tested

. ../share/common.sh

#
# Init
#
t_init
t_srv_run_bg

#
# Step 1
#
t_dbg "[Step 1] Client is requested to send a PUT request with:"\
      "Type = 0(CON); Code = 3(PUT); An arbitrary payload; Content"\
      "type option."

# prepare arbitrary payload
pf=.`basename $0`.payload
p="lots of cool stuff"
${ECHO} -n "${p}" > ${pf}

t_cli_set_type CON
t_cli_set_method PUT
t_cli_set_payload ${pf}

out=`t_cli_run`

t_field_get 1 srv Content-Type 1>/dev/null
[ $? -ne 1 ] || t_die 1 "field must be defined!"

#
# Step 2
#
t_dbg "[Step 2] Sent request contains Type value indicating 0 and Code value"\
      "indicating 3."

t_field_check 1 srv T CON
t_field_check 1 srv Code PUT

#
# Step 3
#
t_dbg "[Step 3] Server displays received information."

# compare hex representations
t_field_check 1 srv Payload `t_str2hex ${p}`

#
# Step 4
#
t_dbg "[Step 4] Server sends response containing: Code = 68(2.04 Changed);"\
      "The Message ID as that of the previous request."

t_field_check 1 cli Code "2.04 (Changed)"
v=`t_field_get 1 srv MID`
t_field_check 1 cli MID "${v}"

#
# Step 5
#
t_dbg "[Step 5] Client displays the received response."

t_dbg "${out}"
if [ "${EC_PLUG_MODE}" != "srv" ]; then
    t_cmp "${out}" "Hello world!"
fi

#
# Cleanup
#
rm -f ${pf}
t_term
