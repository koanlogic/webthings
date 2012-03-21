## TD_COAP_CORE_01
##
## description: Perform GET transaction (CON mode)
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
t_dbg "[Step 1] Client is requested to send a GET request with:"\
      "Type = 0(CON); Code = 1(GET)."

t_cli_set_type CON
t_cli_set_method GET

out=`t_cli_run`

#
# Step 2
#
t_dbg "[Step 2] Sent request contains Type value indicating 0 and Code value"\
      "indicating 1."

t_field_check 1 srv T CON
t_field_check 1 srv Code GET

#
# Step 3
#
t_dbg "[Step 3] Server sends response containing: Code = 69(2.05 Content);"\
      "The same Message ID as that of the previous request; Content type"\
      "option."

t_field_check 1 cli Code "2.05 (Content)"

if [ "${EC_PLUG_MODE}" != "cli" ]; then 
    v=`t_field_get 1 srv MID`
    t_field_check 1 cli MID "${v}"
fi

t_field_get 1 cli Content-Type 1>/dev/null
[ $? -ne 1 ] || t_die ${EC_PLUG_RC_GENERR} "field must be defined!"

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
