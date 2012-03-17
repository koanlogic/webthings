# base address for clients and servers
EC_PLUG_ADDR="coap://[::1]:5683"

# server settings
EC_PLUG_SRV_CMD="../server/coap-server"
EC_PLUG_SRV_ARG_URI="${EC_PLUG_ADDR}"

# other server settings
#EC_PLUG_SRV_ARG_SEP=""         # default: unset

# client settings
EC_PLUG_CLI_CMD="../../client/coap-client"
EC_PLUG_CLI_ARG_URI="${EC_PLUG_ADDR}"
EC_PLUG_CLI_ARG_PATH="/test"
EC_PLUG_CLI_ARG_TYPE="CON"
EC_PLUG_CLI_ARG_METHOD="GET"
EC_PLUG_CLI_ARG_OUTPUT="-"

# client options
#EC_PLUG_CLI_ARG_PAYLOAD=""     # default: unset
#EC_PLUG_CLI_ARG_TOKEN=""       # default: unset
#EC_PLUG_CLI_ARG_BLOCK=""       # default: unset
#EC_PLUG_CLI_ARG_OBS=""         # default: unset

# other client settings
#EC_PLUG_VERBOSE=1              # default: unset
#EC_PLUG_VERBOSE=1              # default: unset

# custom commands 
ECHO=/bin/echo      # default version on mac doesn't like '-n' arg

[ "${EC_PLUG_DUMP}" = "1" ] || \
        ${ECHO} "# [warn] EC_PLUG_DUMP not set,"\
             "no 'check' steps will be performed"


# If EC_PLUG_VERBOSE=1, debugs all strings to standard error.
t_dbg()
{
    [ "${EC_PLUG_VERBOSE}" = "1" ] && ${ECHO} $@ 1>&2
    
    return 0
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

# Wrap a command by debugging it and showing stderr output only if EC_PLUG_VERBOSE=1.
#
# $1    whether to run the process in background
# $@    rest of arguments
t_wrap()
{
    bg=$1
    shift

    t_dbg "# $@ (bg=${bg})"

    if [ "${EC_PLUG_VERBOSE}" = "1" ]; then
        if [ ${bg} -eq 1 ]; then
            $@ &
        else
            $@
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
    t_dbg "# checking value '$1'"

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
t_srv_run()
{
    [ "${EC_PLUG_MODE}" != "cli" ] || return 2

    args=""

    [ -z ${EC_PLUG_SRV_ARG_URI} ] || \
        args="${args} -u ${EC_PLUG_SRV_ARG_URI}"

    [ -z ${EC_PLUG_SRV_ARG_SEP} ] || \
        args="${args} -s ${EC_PLUG_SRV_ARG_SEP}"

    t_wrap 1 "${EC_PLUG_SRV_CMD}" "${args}"
    [ $? -eq 0 ] || t_die 1 "client failed! (rc=$?)"
}

# Set server uri
t_srv_set_uri()
{
    EC_PLUG_SRV_ARG_URI=$1
}

# Set argument for separate response (seconds)
t_srv_set_sep()
{
    EC_PLUG_SRV_ARG_SEP=$1
}

# Run a CoAP client.
t_cli_run()
{
    [ "${EC_PLUG_MODE}" != "srv" ] || return 2

    args=""

    [ -z ${EC_PLUG_CLI_ARG_URI} ] || \
        args="${args} -u ${EC_PLUG_CLI_ARG_URI}${EC_PLUG_CLI_ARG_PATH}"

    [ -z ${EC_PLUG_CLI_ARG_TYPE} ] || \
        args="${args} -M ${EC_PLUG_CLI_ARG_TYPE}"

    [ -z ${EC_PLUG_CLI_ARG_METHOD} ] || \
        args="${args} -m ${EC_PLUG_CLI_ARG_METHOD}"

    [ -z ${EC_PLUG_CLI_ARG_PAYLOAD} ] || \
        args="${args} -p ${EC_PLUG_CLI_ARG_PAYLOAD}"

    [ -z ${EC_PLUG_CLI_ARG_TOKEN} ] || \
        args="${args} -T"

    [ -z ${EC_PLUG_CLI_ARG_BLOCK} ] || \
        args="${args} -B ${EC_PLUG_CLI_ARG_BLOCK}"

    [ -z ${EC_PLUG_CLI_ARG_OBS} ] || \
        args="${args} -O ${EC_PLUG_CLI_ARG_OBS}"

    [ -z ${EC_PLUG_CLI_ARG_OUTPUT} ] || \
        args="${args} -o ${EC_PLUG_CLI_ARG_OUTPUT}"

    t_wrap 0 "${EC_PLUG_CLI_CMD}" "${args}"
    [ $? -eq 0 ] || t_die 1 "client failed! (rc=$?)"
}

# Set client uri
t_cli_set_uri()
{
    EC_PLUG_CLI_ARG_URI=$1
}

# Set client path
t_cli_set_path()
{
    EC_PLUG_CLI_ARG_PATH=$1
}

# Set client message type
t_cli_set_type()
{
    t=$1

    case "${t}" in
        CON|NON)
            EC_PLUG_CLI_ARG_TYPE="${t}" ;;
        *)
            t_die 1 "bad type: ${t}" ;;
    esac
}

# Set client method
t_cli_set_method()
{
    m=$1

    case "${m}" in
        GET|POST|PUT|DELETE)
            EC_PLUG_CLI_ARG_METHOD="${m}" ;;
        *)
            t_die 1 "bad method: ${m}" ;;
    esac
}

# Set client payload
t_cli_set_payload()
{
    EC_PLUG_CLI_ARG_PAYLOAD=$1
}

# Activate client Token option
t_cli_set_token()
{
    EC_PLUG_CLI_ARG_TOKEN=1
}

# Set client Block option
t_cli_set_block()
{
    EC_PLUG_CLI_ARG_BLOCK=$1
}

# Set client Observe option
t_cli_set_observe()
{
    EC_PLUG_CLI_ARG_OBS=$1
}

# Get the value of a field.
#
# $1    packet identifier
# $2    srv|cli
# $3    field name
t_field_get()
{
    [ "${EC_PLUG_DUMP}" = "1" ] || return 2

    id=$1
    srv=$2
    field=$3
    dump="${id}-${srv}.dump"

    t_dbg "# retrieving field '${field}'"

    [ -r "${dump}" ] || t_die 1 "could not find dump file (${dump})!"

    # retrieve line
    xval=`grep "${field}:" "${dump}"`
    [  $? -eq 0 ] || return 1

    # retrieve value
    xval=`${ECHO} ${xval} | cut -d ':' -f 2`

    # remove leading space
    ${ECHO} "${xval}" | sed 's/^ //'
}

# Check that the value of a dumped field is equal to the expected value.
#
# $1    packet identifier
# $2    srv|cli
# $3    field name
# $4    field value
t_field_check()
{
    [ "${EC_PLUG_DUMP}" = "1" ] || return 2

    id=$1
    srv=$2
    field=$3
    val=$4
    dump="${id}-${srv}.dump"

    [ -r "${dump}" ] || t_die 1 "could not find dump file (${dump})!"

    # retrieve line
    xval=`grep "${field}:" "${dump}"`
    [  $? -eq 0 ] || return 1

    # retrieve value
    xval=`${ECHO} ${xval} | cut -d ':' -f 2`

    # remove leading space
    xtrim=`${ECHO} ${xval} | sed 's/^ //'`

    t_dbg "# checking message ${dump} field '${field}': '${xtrim}'"

    # compare result with value    
    [ "${xtrim}" = "${val}" ] || t_die 1 \
            "failed check! (found: '${xtrim}', expected: '${val}')"
}

# Check that the value of a dumped field is different from the given value.
#
# $1    packet identifier
# $2    srv|cli
# $3    field name
# $4    field value
t_field_diff()
{
    [ "${EC_PLUG_DUMP}" = "1" ] || return 2

    id=$1
    srv=$2
    field=$3
    val=$4
    dump="${id}-${srv}.dump"

    [ -r "${dump}" ] || t_die 1 "could not find dump file (${dump})!"

    # retrieve line
    xval=`grep "${field}:" "${dump}"`
    [  $? -eq 0 ] || return 1

    # retrieve value
    xval=`${ECHO} ${xval} | cut -d ':' -f 2`

    # remove leading space
    xtrim=`${ECHO} ${xval} | sed 's/^ //'`

    t_dbg "# checking message ${dump} field '${field}' != '${xtrim}'"

    # compare result with value    
    [ "${xtrim}" != "${val}" ] || t_die 1 \
            "failed check! (found: '${xtrim}', expected: '${val}')"
}

# Check the size of a string.
#
# $1    input string
# $2    min size of string
# $3    max size of string
t_check_len()
{
    [ "${EC_PLUG_DUMP}" = "1" ] || return 2

    s=$1
    min=$2
    max=$3

    t_dbg "# checking length of '${s}' (>=${min}, <=${max})"

    xlen=`${ECHO} -n "${s}" | wc -c | sed -e 's/\ //g'`

    [ ${xlen} -ge ${min} ] || t_die 1 "# bad length!"
    [ ${xlen} -le ${max} ] || t_die 1 "# bad length!"
}

# Convert input string to hex representation.
t_str2hex()
{
    hexval=`${ECHO} -n $@ | xxd -p`

    ${ECHO} "0x${hexval}"
}

__t_timer()
{
    sleep $1

    t_dbg "timer expired! killing processes"

    killall coap-server coap-client
}

t_timer()
{
    __t_timer_int $1 &
}

trap t_term 2 9 15
