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
t_dbg "# Step 1"

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
t_dbg "# Step 2"

t_field_check 1 srv T CON
t_field_check 1 srv Code GET
t_field_check 1 srv Block2 128

#
# Step 3
#
t_dbg "# Step 3"

t_field_check 1 cli Code "2.05 (Content)"
v=`t_field_get 1 srv MID`
t_field_check 1 cli MID "${v}"
t_field_check 1 cli Block2 14  # num=0,m=1,szx=6

#
# Step 4
#
t_dbg "# Step 4"

t_field_check 2 srv T CON
t_field_check 2 srv Code GET

#
# Step 5
#
t_dbg "# Step 5"

t_field_check 2 srv Block2 22  # num=1,m=0,szx=6

#
# Step 6
#
t_dbg "# Step 6"

t_field_check 2 cli Block2 22  # num=1,m=0,szx=6

#
# Step 7
#
t_dbg "# Step 7"

t_dbg "${out}"

#
# Cleanup
#
t_term

