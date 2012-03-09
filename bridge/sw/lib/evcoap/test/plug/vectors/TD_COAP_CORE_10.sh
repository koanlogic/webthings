## TD_COAP_CORE_10
##
## description: Handle request containing Token option
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
t_dbg "# Step 1"

t_cli_set_type CON
t_cli_set_method GET
t_cli_set_token

out=`t_cli_run`

#
# Step 2
#
t_dbg "# Step 2"

t_field_check 1 srv T CON
t_field_check 1 srv Code GET

# retrieve token received by server
token1=`t_field_get 1 srv Token`

# check that size of Token is between 1B and 8B
# (4 and 18 chars include 0x)
t_check_len "${token1}" 4 18

#
# Step 3
#
t_dbg "# Step 3"

t_field_check 1 cli Code "2.05 (Content)"

# retrieve token received by server
token2=`t_field_get 1 cli Token`

# check that size of Token is between 1B and 8B
# (4 and 18 chars include 0x)
t_check_len "${token2}" 4 18

# compare returned token with sent token
t_cmp "${token1}" "${token2}"

# compare hex representations
t_field_check 1 cli Payload `t_str2hex "Hello world!"`

t_field_get 1 cli Content-Type 1>/dev/null
[ $? -ne 1 ] || t_die 1 "field should be defined!"

#
# Step 4
#
t_dbg "# Step 4"

t_dbg "${out}"
if [ "${EC_PLUG_MODE}" != "srv" ]; then
    t_cmp "${out}" "Hello world!"
fi

#
# Cleanup
#
t_term
