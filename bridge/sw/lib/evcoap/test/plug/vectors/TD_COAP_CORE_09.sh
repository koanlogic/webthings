## TD_COAP_CORE_09
##
## description: Perform GET transaction with a separate response
## status: incomplete, tested

. ../share/common.sh

t_die 1 "# Incomplete!"


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
t_cli_set_path /separate

out=`t_cli_run`

#
# Step 2
#
t_dbg "# Step 2"

t_field_check 1 srv T CON
t_field_check 1 srv Code GET

cmid=`t_field_get 1 srv MID`
[ $? -ne 1 ] || t_die 1 "field must be defined!"

#
# Step 3
#
t_dbg "# Step 3"

t_field_check 1 cli T ACK
t_field_check 1 cli MID "${cmid}"

# TODO check empty payload

#
# Step 4
#
t_dbg "# Step 4"

t_field_check 2 cli T CON
t_field_check 2 cli Code "2.05 (Content)"
# TODO check payload=content, content-type

#
# Step 5
#
t_dbg "# Step 5"

t_field_check 2 srv T ACK
# msgid same as response
# empty payload

#
# Step 6
#
t_dbg "# Step 6"

t_dbg "${out}"
if [ "${EC_PLUG_MODE}" != "srv" ]; then
    t_cmp "${out}" "Hello world!"
fi

#
# Cleanup
#
t_term
