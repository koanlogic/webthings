# base address for clients and servers
if [ -z ${EC_PLUG_ADDR} ]; then
    EC_PLUG_ADDR="coap://[::1]:5683"
fi

# server settings
if [ -z ${EC_PLUG_SRV_CMD} ]; then
    EC_PLUG_SRV_CMD="../server/coap-server"
fi
EC_PLUG_SRV_ARG_URI="${EC_PLUG_ADDR}"

# other server settings
#EC_PLUG_SRV_ARG_SEP=""         # default: unset

# client settings
if [ -z ${EC_PLUG_CLI_CMD} ]; then
    EC_PLUG_CLI_CMD="../../client/coap-client"
fi
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

# other settings
EC_PLUG_PIDS=""
EC_PLUG_PIDS_FILE=".pids"

# custom commands 
ECHO=/bin/echo      # default version on mac doesn't like '-n' arg

[ "${EC_PLUG_DUMP}" = "1" ] || \
        ${ECHO} "# [warn] EC_PLUG_DUMP not set,"\
             "no 'check' steps will be performed"


# If EC_PLUG_VERBOSE=1, debugs all strings to standard error.
t_dbg()
{
    [ "${EC_PLUG_VERBOSE}" = "1" ] && ${ECHO} "# $@" 1>&2
    
    return 0
}

# Print a message and exit with return code $1.
t_die()
{
    rc=$1
    shift

    t_dbg "$@"

    t_term ${rc}
}

# Wrap a command by debugging it and showing stderr output only if EC_PLUG_VERBOSE=1.
#
# $1    whether to run the process in background
# $@    rest of arguments
t_wrap()
{
    bg=$1
    shift

    t_dbg "$@ (bg=${bg})"

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

    t_dbg "pid: $!"
}

# Compare two strings and fail if they are different.
t_cmp()
{
    t_dbg "checking value '$1'"

    if [ "$1" = "$2" ]; then
        return 0
    else 
        t_die 1 "comparison failed! ($1,$2)"
    fi
}

# Initialise test
t_init()
{
    # remove any pre-existing dump or cache files
    rm -f *.dump "${EC_PLUG_PIDS_FILE}"
}

# Cleanup test - kills all processes.
t_term()
{
    # no return code specified = success
    rc=$1
    [ -z ${rc} ] && rc=0

    if [ ${rc} -eq 0 ]; then
        t_dbg "success"
    else 
        t_dbg "failure (rc=${rc})"
    fi

    #t_dbg "jobs left: `jobs -p`"
    
    # kill specified pids
    kill ${EC_PLUG_PIDS} 2>/dev/null

    # kill processes spawned by children
    if [ -r ${EC_PLUG_PIDS_FILE} ]; then
        kill `cat "${EC_PLUG_PIDS_FILE}"` 2>/dev/null
    fi

    # kill anything remaining
    kill `jobs -p` 2>/dev/null

    exit ${rc}
}

__t_srv_run()
{
    [ "${EC_PLUG_MODE}" != "cli" ] || return 2

    args=""
    fg=$1

    [ -z ${EC_PLUG_SRV_ARG_URI} ] || \
        args="${args} -u ${EC_PLUG_SRV_ARG_URI}"

    [ -z ${EC_PLUG_SRV_ARG_SEP} ] || \
        args="${args} -s ${EC_PLUG_SRV_ARG_SEP}"

    t_wrap ${fg} "${EC_PLUG_SRV_CMD}" "${args}" "$@"
}

# Run a CoAP server in foreground.
t_srv_run()
{
    __t_srv_run 0

    # might have been killed intentionally, so don't die!
    [ $? -eq 0 ] || t_dbg 1 "server failed! (rc=$?)"
}

# Run a CoAP server in background.
t_srv_run_bg()
{
    __t_srv_run 1

    # add pid to list of processes to be killed
    t_pid_add $!
}


# Set server uri
t_srv_set_uri()
{
    [ -z $1 ] && t_die 1 "URI must be defined!"

    EC_PLUG_SRV_ARG_URI=$1
}

# Set argument for separate response (seconds)
t_srv_set_sep()
{
    [ -z $1 ] && unset EC_PLUG_CLI_ARG_SEP

    EC_PLUG_SRV_ARG_SEP=$1
}

__t_cli_run()
{
    [ "${EC_PLUG_MODE}" != "srv" ] || return 2

    fg=$1
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

    t_wrap ${fg} "${EC_PLUG_CLI_CMD}" "${args}" "$@"
}

# Run a CoAP client in foreground.
t_cli_run()
{
    __t_cli_run 0

    # might have been killed intentionally, so don't die!
    [ $? -eq 0 ] || t_dbg 1 "client failed! (rc=$?)"
}

# Run a CoAP client in background.
t_cli_run_bg()
{
    __t_cli_run 1

    # add pid to list of processes to be killed
    t_pid_add $!
}

# Set client uri
t_cli_set_uri()
{
    [ -z $1 ] && t_die 1 "URI must be defined!"

    EC_PLUG_CLI_ARG_URI=$1
}

# Set client path
t_cli_set_path()
{
    [ -z $1 ] && t_die 1 "Path must be defined!"

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
    [ -z $1 ] && t_die 1 "Method must be defined!"

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
    [ -z $1 ] && unset EC_PLUG_CLI_ARG_PAYLOAD

    EC_PLUG_CLI_ARG_PAYLOAD=$1
}

# Activate client Token option
t_cli_set_token()
{
    [ -z $1 ] && unset EC_PLUG_CLI_ARG_TOKEN

    EC_PLUG_CLI_ARG_TOKEN=1
}

# Set client Block option
t_cli_set_block()
{
    [ -z $1 ] && unset EC_PLUG_CLI_ARG_BLOCK

    EC_PLUG_CLI_ARG_BLOCK=$1
}

# Set client Observe option
t_cli_set_observe()
{
    [ -z $1 ] && unset EC_PLUG_CLI_ARG_OBS

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

    t_dbg "retrieving field '${field}' from '${dump}'"

    [ -r "${dump}" ] || return 1

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

    [ -r "${dump}" ] || t_die 1 "missing dump: '${dump}'"

    # retrieve line
    xval=`grep "${field}:" "${dump}"`
    [  $? -eq 0 ] || t_die 1 "field '${field}' not found!"

    # retrieve value
    xval=`${ECHO} ${xval} | cut -d ':' -f 2`

    # remove leading space
    xtrim=`${ECHO} ${xval} | sed 's/^ //'`

    t_dbg "checking message ${dump} field '${field}': '${xtrim}'"

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

    [ -r "${dump}" ] || t_die 1 "missing dump: '${dump}'"

    # retrieve line
    xval=`grep "${field}:" "${dump}"`
    [  $? -eq 0 ] || return 1

    # retrieve value
    xval=`${ECHO} ${xval} | cut -d ':' -f 2`

    # remove leading space
    xtrim=`${ECHO} ${xval} | sed 's/^ //'`

    t_dbg "checking message ${dump} field '${field}' != '${xtrim}'"

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

    t_dbg "checking length of '${s}' (>=${min}, <=${max})"

    xlen=`${ECHO} -n "${s}" | wc -c | sed -e 's/\ //g'`

    [ ${xlen} -ge ${min} ] || t_die 1 "bad length!"
    [ ${xlen} -le ${max} ] || t_die 1 "bad length!"
}

# Convert input string to hex representation.
#
# $1    input string
t_str2hex()
{
    hexval=`${ECHO} -n $@ | xxd -p`

    ${ECHO} -n "0x${hexval}"
}

# Convert hex data to string.
# 
# $1    input hex representation
t_hex2str()
{
    ${ECHO} -n $1 | sed 's/^0x//' | xxd -p -r
}

__t_timer()
{
    sleep $1

    shift

    for cmd in "$@"; do
        t_dbg "running command: '${cmd}'"
        ${cmd} 1>&2
    done

    ${ECHO} -n "`jobs -p` " >> ${EC_PLUG_PIDS_FILE}
}

# Run commands after a number of seconds
#
# $1    seconds
# $@    string of commands
t_timer()
{
    [ -z $1 ] && t_die 1 "seconds undefined!"
    s=$1
    [ -z "$2" ] && t_die 1 "commands undefined!"

    t_dbg "timer secs: $1"

    shift

    t_dbg "timer cmds: $@"

    __t_timer ${s} "$@" &
}

# Append to list of PIDS to be killed upon termination
t_pid_add()
{
    EC_PLUG_PIDS="${EC_PLUG_PIDS} $@"
}

trap t_term 2 9 15
