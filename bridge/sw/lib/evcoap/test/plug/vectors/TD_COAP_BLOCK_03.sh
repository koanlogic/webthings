## TD_COAP_BLOCK_03
##
## description: Handle PUT blockwise transfer for large resource
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
t_dbg "[Step 1] Client is requested to update resource /large-update on"\
      "Server."

pf=.`basename $0`.payload
cp /etc/passwd ${pf}

t_cli_set_type CON
t_cli_set_method PUT
t_cli_set_path /large_update
t_cli_set_payload ${pf}

out=`t_cli_run`
#echo ${out}
t_cli_set_method GET
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
t_dbg "[Step 2] Client sends a PUT request containing Block1 option"\
      "indicating block number 0 and block size."

#
# Step 3
#
t_dbg "[Step 3] Client sends further requests containing Block1 option"\
      "indicating block number and size."

#
# Step 4
#
t_dbg "[Step 4] Server indicates presence of the complete updated resource"\
      "/large-update."

#
# Cleanup
#
t_term
