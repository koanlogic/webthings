## TD_COAP_BLOCK_01
##
## description: Handle GET blockwise transfer for large resource (early negotiation)
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
t_cli_set_block 256

out=`t_cli_run`

#
# Step 2
#
t_dbg "[Step 2] Client sends a GET request containing Block2 option"\
      "indicating block number 0 and desired block size."

t_field_check 1 srv T CON
t_field_check 1 srv Code GET
t_field_check 1 srv Block2 4  # num=0,m=0,szx=4

#
# Step 3
#
t_dbg "[Step 3] Server sends response containing Block2 option indicating"\
      "block number and size."

t_field_check 1 cli Code "2.05 (Content)"
v=`t_field_get 1 srv MID`
t_field_check 1 cli MID "${v}"
t_field_check 1 cli Block2 12  # num=0,m=1,szx=4

#
# Step 4
#
t_dbg "[Step 4] Client send GET requests for further blocks."

for i in `seq 2 6`; do
    t_field_check ${i} srv T CON
    t_field_check ${i} srv Code GET
done

#
# Step 5
#
t_dbg "[Step 5] Each request contains Block2 option indicating block number"\
      "of the next block and size of the last received block."

t_field_check 2 srv Block2 20  # num=1,m=0,szx=4
t_field_check 3 srv Block2 36  # num=2,m=0,szx=4
t_field_check 4 srv Block2 52  # num=3,m=0,szx=4
t_field_check 5 srv Block2 68  # num=4,m=0,szx=4
t_field_check 6 srv Block2 84  # num=5,m=0,szx=4

#
# Step 6
#
t_dbg "[Step 6] Server sends further responses containing Block2 option"\
      "indicating block number and size."

t_field_check 2 cli Block2 28  # num=1,m=1,szx=4
t_field_check 3 cli Block2 44  # num=2,m=1,szx=4
t_field_check 4 cli Block2 60  # num=3,m=1,szx=4
t_field_check 5 cli Block2 76  # num=4,m=1,szx=4
t_field_check 6 cli Block2 84  # num=5,m=0,szx=4

#
# Step 7
#
t_dbg "[Step 7] Client displays the received information."

t_dbg "${out}"

#
# Cleanup
#
t_term
