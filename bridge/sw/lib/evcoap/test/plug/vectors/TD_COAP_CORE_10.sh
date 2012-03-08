## TD_COAP_CORE_10
##
## description: Handle request containing Token option
## status: complete,tested

. ../share/common.sh

#
# Init
#
t_init
t_run_srv

#
# Step 1
#
t_dbg "# Step 1"

# activate Token option
out=`t_run_cli GET CON "" /test "" "1"`

#
# Step 2
#
t_dbg "# Step 2"

t_check_field 1 srv T CON
t_check_field 1 srv Code GET

# retrieve token received by server
token1=`t_get_field 1 srv Token`

# check that size of Token is 8 (10 including '0x')
t_check_len "${token1}" 18

#
# Step 3
#
t_dbg "# Step 3"

t_check_field 1 cli Code "2.05 (Content)"

# retrieve token received by server
token2=`t_get_field 1 cli Token`

# check that size of Token is 8B (8*2 + 2 including '0x')
t_check_len "${token2}" 18

# compare returned token with sent token
t_cmp "${token1}" "${token2}"

#
# Step 4
#
t_dbg "# Step 4"

t_dbg "${out}"
if [ "${MODE}" != "srv" ]; then
    t_cmp "${out}" "Hello world!"
fi

#
# Cleanup
#
t_term
