#VERBOSE=1
SRV_ADDR="coap://[::1]:5683"
CLI_CMD="../../client/coap-client"
SRV_CMD="../server/coap-server"
ECHO=/bin/echo

[ "${DUMP_PDUS}" = "1" ] || \
        ${ECHO} "# [warn] DUMP_PDUS not set,"\
             "no 'check' steps will be performed"


# If VERBOSE=1, debugs all strings to standard error.
t_dbg()
{
    [ "${VERBOSE}" = "1" ] && ${ECHO} $@ 1>&2
}

# Print a message and exit with return code $1.
t_die()
{
    rc=$1
    shift
    ${ECHO} "$@"
    t_term
    exit ${rc}
}

# Wrap a command by debugging it and showing stderr output only if VERBOSE=1.
#
# $1    whether to run the process in background
# $@    rest of arguments
t_wrap()
{
    bg=$1
    shift

    t_dbg "# $@ (bg=${bg})"

    if [ "${VERBOSE}" = "1" ]; then
        if [ ${bg} -eq 1 ]; then
            $@ ${post} &
        else
            $@ ${post}
        fi
    else
        if [ ${bg} -eq 1 ]; then
            $@ 2>/dev/null &
        else
            $@ 2>/dev/null
        fi
    fi
}

# Compare two strings and fail if they are different.
t_cmp()
{
    t_dbg "# checking value $1"

    if [ "$1" = "$2" ]; then
        return 0
    else 
        t_die 1 "comparison failed! ($1,$2)"
    fi
}

# Initialise test - does nothing yet.
t_init()
{
    return 0
}

# Cleanup test - kills all processes.
t_term()
{
    j=`jobs -p`
    kill ${j} 2>/dev/null
}

# Run a CoAP server.
#
# $1    address     <uri>                   (default is coap://[::1])
t_run_srv()
{
    [ "${MODE}" != "cli" ] || return 0

    addr=$1
    [ -z ${addr} ] && addr="${SRV_ADDR}"

    t_wrap 1 "${SRV_CMD}" -u "${addr}"
}

# Run a CoAP client.
#
# $1    method          <GET|POST|PUT|DELETE>   (default is GET)
# $2    message         <CON|NON>               (default is CON)
# $3    address         <uri>                   (default is coap://[::1])
# $4    resource        <rsrc>                  (default is /test)
# $5    payload         <rsrc>                  (default is /test)
# $6    token option    <1|0>                   (default is 0)
#
t_run_cli()
{
    [ "${MODE}" != "srv" ] || return 0

    meth=$1
    msg=$2
    addr=$3
    rsrc=$4
    payload=$5
    token=$6

    # set defaults for empty string vals
    [ "${meth}" = "" ] && meth="GET"
    [ -z ${msg} ] && msg="CON"
    [ -z ${addr} ] && addr="${SRV_ADDR}"
    [ -z ${rsrc} ] && rsrc="/test"

    # initialise default arguments
    args="-m ${meth} -M ${msg} -u ${addr}${rsrc} -o -"

    # if specified, add optional payload
    [ -z ${payload} ] || args="${args} -p ${payload}"

    # if specified, enable Token option
    [ "${token}" = "1" ] && args="${args} -T"

    t_wrap 0 "${CLI_CMD}" "${args}"
    [ $? -eq 0 ] || t_die 1 "client failed! (rc=$?)"
}

# Get the value of a field.
#
# $1    packet identifier
# $2    srv|cli
# $3    field name
t_get_field()
{
    [ "${DUMP_PDUS}" = "1" ] || return

    id=$1
    srv=$2
    field=$3

    # retrived dumped value field
    xval=`grep "${field}:" ${id}-${srv}.dump | cut -d ':' -f 2`

    # remove leading space
    ${ECHO} "${xval}" | sed 's/^ //'
}

# Check the size of a string.
#
# $1    input string
# $2    expectes size of string
t_check_len()
{
    s=$1
    len=$2

    t_dbg "# checking length of '${s}' (expected ${len})"

    xlen=`${ECHO} -n "${s}" | wc -c | sed -e 's/\ //g'`

    [ ${xlen} = ${len} ] || t_die 1 "# bad length!"
}

# Check that the value of a dumped field is equal to the expected value.
#
# $1    packet identifier
# $2    srv|cli
# $3    field name
# $4    field value
t_check_field()
{
    [ "${DUMP_PDUS}" = "1" ] || return

    id=$1
    srv=$2
    field=$3
    val=$4

    # retrived dumped value field
    xval=`grep "${field}:" ${id}-${srv}.dump | cut -d ':' -f 2`

    # remove leading space
    xtrim=`${ECHO} ${xval} | sed 's/^ //'`

    t_dbg "# checking message ${id}-${srv} field ${field}: ${xtrim}"

    # compare result with value    
    [ "${xtrim}" = "${val}" ] || t_die 1 \
            "failed check! (found: '${xtrim}'. expected: '${val}')"
}

# Check that the value of a dumped field is different from the given value.
#
# $1    packet identifier
# $2    srv|cli
# $3    field name
# $4    field value
t_diff_field()
{
    [ "${DUMP_PDUS}" = "1" ] || return

    id=$1
    srv=$2
    field=$3
    val=$4

    # retrived dumped value field
    xval=`grep "${field}:" ${id}-${srv}.dump | cut -d ':' -f 2`

    # remove leading space
    xtrim=`${ECHO} ${xval} | sed 's/^ //'`

    t_dbg "# checking message ${id}-${srv} field ${field} != ${xtrim}"

    # compare result with value    
    [ "${xtrim}" != "${val}" ] || t_die 1 \
            "failed check! (found: '${xtrim}'. expected a different value')"
}

# Convert input string to hex representation.
t_str2hex()
{
    hexval=`${ECHO} $@ | xxd -p`

    ${ECHO} "0x${hexval}"
}

trap t_term 2 9 15
