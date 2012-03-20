## TD_COAP_CORE_08
##
## description: Perform DELETE transaction (NON mode)
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
t_dbg "[Step 1] Client is requested to send a DELETE request with:"\
      "Type = 1(NON); Code = 4(DELETE)."

t_cli_set_type NON
t_cli_set_method DELETE

out=`t_cli_run`

#
# Step 2
#
t_dbg "[Step 2] Sent request contains Type value indicating 1 and Code value"\
      "indicating 4."

t_field_check 1 srv T NON
t_field_check 1 srv Code DELETE

#
# Step 3
#
t_dbg "[Step 3] Server sends response containing: Type = 1(NON);"\
      "Code = 66(2.02 Deleted)."

t_field_check 1 cli T NON
t_field_check 1 cli Code "2.02 (Deleted)"
v=`t_field_get 1 srv MID`
t_field_diff 1 cli MID "${v}"

#
# Step 4
#
t_dbg "[Step 4] Client displays the received information."

t_dbg "${out}"
if [ "${EC_PLUG_MODE}" != "srv" ]; then
    t_cmp "${out}" "Hello world!"
fi

#
# Cleanup
#
t_term
