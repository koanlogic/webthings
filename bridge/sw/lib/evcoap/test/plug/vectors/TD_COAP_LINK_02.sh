## TD_COAP_LINK_02
##
## description: Use filtered requests for limiting discovery results
## status: complete, tested

. ../share/common.sh

rt="LargeTest"

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
t_cli_set_path "/.well-known/core?rt=${rt}"

out=`t_cli_run`

#
# Step 2
#
t_dbg "# Step 2"

t_field_check 1 srv T CON
t_field_check 1 srv Code GET
#t_field_check 1 srv URI-Path .well-known/core      # FIXME
t_field_check 1 srv URI-Query "rt=${rt}"

#
# Step 3
#
t_dbg "# Step 3"

t_field_check 1 cli Code "2.05 (Content)"
v=`t_field_get 1 srv MID`
t_field_check 1 cli MID "${v}"
t_field_check 1 cli Content-Type "40"   # application/link-format

# check in Payload that we only have resources of type rt
p=`t_field_get 1 cli Payload`
wkc=`t_hex2str "${p}"`

# grep should fail (no results returned)
${ECHO} -n "${wkc}" | grep -v "rt=\"${rt}\""
[ $? -eq 0 ] && t_die 1 "found bad resource types!"

#
# Step 4
#
t_dbg "# Step 4"

t_dbg "${out}"

#
# Cleanup
#
t_term
