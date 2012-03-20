## TD_COAP_BLOCK_04
##
## description: Handle POST blockwise transfer for large resource
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
t_dbg "[Step 1] Client is requested to create a new resource on Server."

pf=.`basename $0`.payload
cp /etc/passwd ${pf}

t_cli_set_type CON
t_cli_set_method POST
t_cli_set_path /large-create
t_cli_set_payload ${pf}
t_cli_set_block 1024

out=`t_cli_run`

#
# Step 2
#
t_dbg "[Step 2] Client sends a POST request containing Block1 option"\
      "indicating block number 0 and block size."

t_field_check 1 srv T CON
t_field_check 1 srv Code POST
t_field_check 1 srv Block1 14  # num=0,m=1,szx=6

#
# Step 3
#
t_dbg "[Step 3] Client sends further requests containing Block1 option"\
      "indicating block number and size."

t_field_check 2 srv Block1 30   # num=1,m=1,szx=6
t_field_check 3 srv Block1 46   # num=2,m=1,szx=6
t_field_check 4 srv Block1 62   # num=3,m=1,szx=6
t_field_check 5 srv Block1 78   # num=4,m=1,szx=6
#...

#
# Step 4
#
t_dbg "[Step 4] Server indicates presence of the complete new resource."

t_cli_set_method GET
t_cli_run > .fout
diff .fout ${pf}
[ $? -ne 0 ] && t_die 1 "GET doesn't match PUT"

#
# Cleanup
#
t_term
