## TD_COAP_CORE_05
##
## description: Perform GET transaction (NON mode)
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
      "Type = 1(NON); Code = 1(GET)."

t_cli_set_type NON
t_cli_set_method GET

out=`t_cli_run`

#
# Step 2
#
t_dbg "[Step 2] Sent request contains Type value indicating 1 and Code value"\
      "indicating 1."

t_field_check 1 srv T NON
t_field_check 1 srv Code GET

#
# Step 3
#
t_dbg "[Step 3] Server sends response containing: Type = 1(NON);"\
      "Code= 69(2.05 Content); Content type option."

t_field_check 1 cli T NON
t_field_check 1 cli Code "2.05 (Content)"
v=`t_field_get 1 srv MID`
t_field_diff 1 cli MID "${v}"

t_field_get 1 cli Content-Type 1>/dev/null
[ $? -ne 1 ] || t_die ${EC_PLUG_RC_GENERR} "field must be defined!"

#
# Step 4 
#
t_dbg "[Step 4] Client displays the received information."

t_dbg "${out}"

#
# Cleanup
#
t_term
