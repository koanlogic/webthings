## TD_COAP_CORE_11
##
## description: Handle request not containing Token option
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

# no Token option (= default)
out=`t_run_cli GET CON "" /test`

#
# Step 2
#
t_dbg "# Step 2"

t_check_field 1 srv T CON
t_check_field 1 srv Code GET

# make sure token is undefined
token1=`t_get_field 1 srv Token`
t_cmp "${token1}" ""

#
# Step 3
#
t_dbg "# Step 3"

t_check_field 1 cli Code "2.05 (Content)"

# make sure token is undefined
token2=`t_get_field 1 cli Token`
t_cmp "${token2}" ""

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
