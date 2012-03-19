## TD_COAP_BLOCK_02
##
## description: Handle GET blockwise transfer for large resource (late negotiation)
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
t_dbg "[Step 1] Client is requested to retrieve resource /large."

t_cli_set_type CON
t_cli_set_method GET
t_cli_set_path /large

out=`t_cli_run`

#
# Step 2
#
t_dbg "[Step 2] Client sends a GET request not containing Block2 option."

t_field_check 1 srv T CON
t_field_check 1 srv Code GET
t_field_get 1 srv Block2 1>/dev/null
[ $? -eq 0 ] && t_die 1 "field must be undefined!"

#
# Step 3
#
t_dbg "[Step 3] Server sends response containing Block2 option indicating"\
      "block number and size."

t_field_check 1 cli Code "2.05 (Content)"
v=`t_field_get 1 srv MID`
t_field_check 1 cli MID "${v}"
t_field_check 1 cli Block2 14  # num=0,m=1,szx=6

#
# Step 4
#
t_dbg "[Step 4] Client send GET requests for further blocks."

t_field_check 2 srv T CON
t_field_check 2 srv Code GET

#
# Step 5
#
t_dbg "[Step 5] Each request contains Block2 option indicating block number"\
      "of the next block and size of the last received block or the desired"\
      "size of next block."

t_field_check 2 srv Block2 22  # num=1,m=0,szx=6

#
# Step 6
#
t_dbg "[Step 6] Server sends further responses containing Block2 option"\
      "indicating block number and size."

t_field_check 2 cli Block2 22  # num=1,m=0,szx=6

#
# Step 7
#
t_dbg "[Step 7] Client displays the received information."

t_dbg "${out}"

#
# Cleanup
#
t_term
