## TD_COAP_BLOCK_01
##
## description: Handle GET blockwise transfer for large resource (early negotiation)
## status: incomplete,untested

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

t_cli_set_type CON
t_cli_set_method GET
t_cli_set_path /large
bsz=128
t_cli_set_block ${bsz}

out=`t_cli_run`

#
# Step 2
#
t_dbg "# Step 2"

t_field_check 1 srv T CON
t_field_check 1 srv Code GET
#t_field_check 1 srv Block2 ${bsz}

#
# Step 3
#
t_dbg "# Step 3"

t_field_check 1 cli Code "2.05 (Content)"
v=`t_field_get 1 srv MID`
t_field_check 1 cli MID "${v}"

#check Block2,sz

t_field_get 1 cli Content-Type 1>/dev/null
[ $? -ne 1 ] || t_die 1 "field must be defined!"

#
# Step 7
#
t_dbg "# Step 7"

t_dbg "${out}"
#if [ "${EC_PLUG_MODE}" != "srv" ]; then
#    t_cmp "${out}" "Hello world!"
#fi

#
# Cleanup
#
t_term
