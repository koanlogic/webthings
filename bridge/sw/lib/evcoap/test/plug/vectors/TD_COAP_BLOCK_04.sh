## TD_COAP_BLOCK_04
##
## description: Handle POST blockwise transfer for large resource
## status: incomplete,tested

. ../share/common.sh

#
# Init
#
t_init
t_srv_run

#
# Step 1
#
t_dbg "[Step 1] Client is requested to create a new resource on Server."

pf=.`basename $0`.payload
cp /etc/passwd ${pf}

t_cli_set_type CON
t_cli_set_method POST
t_cli_set_path /large_create
t_cli_set_payload ${pf}

out=`t_cli_run`
#echo ${out}

#t_cli_set_method GET
#out=`t_cli_run`
#t_cli_run > FOUT
#${ECHO} -n "XXX 1" ${out}
#${ECHO} -n "XXX 2" `cat ${pf}`
#fp=`cat ${pf}` > FP`

#diff FOUT ${pf}


#rm -f ${pf}
echo "# [warn] incomplete!"
t_term
exit 0

#
# Step 2
#
t_dbg "[Step 2] Client sends a POST request containing Block1 option"\
      "indicating block number 0 and block size."

t_field_check 1 srv T CON
t_field_check 1 srv Code GET
t_field_check 1 srv Block2 128

#
# Step 3
#
t_dbg "[Step 3] Client sends further requests containing Block1 option"\
      "indicating block number and size."

t_field_check 1 cli Code "2.05 (Content)"
v=`t_field_get 1 srv MID`
t_field_check 1 cli MID "${v}"
t_field_check 1 cli Block2 14  # num=0,m=1,szx=6

#
# Step 4
#
t_dbg "[Step 4] Server indicates presence of the complete new resource."

t_field_check 2 srv T CON
t_field_check 2 srv Code GET

#
# Cleanup
#
t_term
