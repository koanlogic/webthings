## TD_COAP_CORE_12
##
## description: Handle request containing several URI-Path options
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
t_cli_set_path /seg1/seg2/seg3

out=`t_cli_run`

#
# Step 2
#
t_dbg "# Step 2"

t_field_check 1 srv T CON
t_field_check 1 srv Code GET

# check that we have all 3 URI-Path Options
if [ "${DUMP_PDUS}" = "1" ]; then
    f="1-srv.dump"
    grep "URI-Path: seg1" "${f}" >/dev/null
    [ $? -eq 0 ] || t_die 1 "seg1 not found!"
    grep "URI-Path: seg2" "${f}" >/dev/null
    [ $? -eq 0 ] || t_die 1 "seg2 not found!"
    grep "URI-Path: seg3" "${f}" >/dev/null
    [ $? -eq 0 ] || t_die 1 "seg3 not found!"
fi

#
# Step 3
#
t_dbg "# Step 3"

t_field_check 1 cli Code "2.05 (Content)"

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
