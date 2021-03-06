# base address for clients and servers
if [ -z ${EC_PLUG_ADDR} ]; then
    EC_PLUG_ADDR="coap://[::1]:5683"
fi

# server settings
if [ -z ${EC_PLUG_SRV_CMD} ]; then
    EC_PLUG_SRV_CMD="../../server/coap-server"
fi
if [ -z ${EC_PLUG_SRV_ARG_FILE} ]; then
    EC_PLUG_SRV_ARG_FILE="../../server/coap-server-plug.conf"
fi

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
#EC_PLUG_CLI_ARG_RETRY="3"      # default: unset
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

# error codes
EC_PLUG_RC_SUCCESS=0            # test succeeded
EC_PLUG_RC_GENERR=1             # test failed
EC_PLUG_RC_BADPARAMS=2          # bad input parameters
EC_PLUG_RC_NOTAPPLICABLE=3      # test not applicable given settings
EC_PLUG_RC_UNIMPLEMENTED=4      # feature not implemented
EC_PLUG_RC_INTERRUPTED=5        # interrupted by signal

# other internals
ec_plug_first=1

# startup warnings
[ "${EC_PLUG_DUMP}" = "1" ] || \
        ${ECHO} "# [warn] EC_PLUG_DUMP not set,"\
             "no 'check' steps will be performed"

# create a local link to plugtest embfs
ln -sf ../../server/plugtest .

# If EC_PLUG_VERBOSE=1, debugs all strings to standard error.
t_dbg()
{
    [ "${EC_PLUG_VERBOSE}" = "1" ] && ${ECHO} "# $@" 1>&2
    
    return ${EC_PLUG_RC_SUCCESS}
}

# Print a message and exit with return code $1.
t_die()
{
    rc=$1
    shift

    ${ECHO} "$@"

    t_term ${rc}
}

# Convert a return code to string representation
t_rc2str()
{
    rc=$1

    case ${rc} in
        ${EC_PLUG_RC_SUCCESS})
            ${ECHO} "success" ;;
        ${EC_PLUG_RC_GENERR})
            ${ECHO} "test failed" ;;
        ${EC_PLUG_RC_BADPARAMS})
            ${ECHO} "bad parameters" ;;
        ${EC_PLUG_RC_NOTAPPLICABLE})
            ${ECHO} "test not applicable" ;;
        ${EC_PLUG_RC_UNIMPLEMENTED})
            ${ECHO} "not implemented" ;;
        ${EC_PLUG_RC_INTERRUPTED})
            ${ECHO} "interrupted by signal" ;;
        *)
            t_die ${EC_PLUG_RC_GENERR} "Bad return code: ${rc}!"
    esac
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
}

# Compare two strings and fail if they are different.
t_cmp()
{
    t_dbg "checking value '$1'"

    if [ "$1" = "$2" ]; then
        return ${EC_PLUG_RC_SUCCESS}
    else 
        t_die ${EC_PLUG_RC_GENERR} "comparison failed! ($1,$2)"
    fi
}

# Initialise test
t_init()
{
    # remove any pre-existing dump or cache files
    rm -f *.dump "${EC_PLUG_PIDS_FILE}"

    # print out environment variables (debug mode only)
    t_dbg "Env:"
    t_dbg "  EC_PLUG_DUMP=${EC_PLUG_DUMP}"
    t_dbg "  EC_PLUG_MODE=${EC_PLUG_MODE}"
    t_dbg "  EC_PLUG_VERBOSE=${EC_PLUG_VERBOSE}"
    t_dbg
}

# Cleanup test - kills all processes.
t_term()
{
    # no return code specified = success
    rc=$1
    [ -z ${rc} ] && rc=0

    rcs=`t_rc2str ${rc}`

    if [ ${rc} -eq 0 ]; then
        t_dbg "success"
    else 
        ${ECHO} "failure (rc=${rc}: '${rcs}')"
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

__t_applicable()
{
    mode=$1

    [ "${EC_PLUG_DUMP}" = "1" ] || return 1

    case ${mode} in
        cli|srv)
           [ -z ${EC_PLUG_MODE} ] && return 0
           [ "${EC_PLUG_MODE}" == "${mode}" ] || return 1
           ;;
        *)
            t_die 1 "invalid mode: ${mode}"
    esac

    return 0
}

__t_srv_run()
{
    [ "${EC_PLUG_MODE}" != "cli" ] || return ${EC_PLUG_RC_NOTAPPLICABLE}

    args=""
    fg=$1
    shift

    [ -z ${EC_PLUG_SRV_ARG_FILE} ] || \
        args="${args} -f ${EC_PLUG_SRV_ARG_FILE}"

    [ -z ${EC_PLUG_SRV_ARG_SEP} ] || \
        args="${args} -s ${EC_PLUG_SRV_ARG_SEP}"

    t_wrap ${fg} "${EC_PLUG_SRV_CMD}" "${args}" "$@"
}

# Run a CoAP server in foreground.
t_srv_run()
{
    __t_srv_run 0

    # upon failure, don't die if killed intentionally (signal) or return code
    # is not applicable
    case $? in ${EC_PLUG_RC_SUCCESS}|\
        ${EC_PLUG_RC_INTERRUPTED}|\
        ${EC_PLUG_RC_NOTAPPLICABLE})
            return 0
            ;;
        *)
            t_dbg 1 "server failed! (rc=$?)"
    esac
}

# Run a CoAP server in background.
t_srv_run_bg()
{
    __t_srv_run 1

    # add pid to list of processes to be killed
    t_pid_add $!

    sleep 1

    # if we are in server-only mode, user determines start of test
    if [ "${EC_PLUG_MODE}" = "srv" ]; then
        if [ ${ec_plug_first} -eq 1 ]; then
            ec_plug_first=0
            t_prompt
        fi
    fi
}

# Set argument for separate response (seconds)
t_srv_set_sep()
{
    [ -z $1 ] && unset EC_PLUG_CLI_ARG_SEP

    EC_PLUG_SRV_ARG_SEP=$1
}

__t_cli_run()
{
    [ "${EC_PLUG_MODE}" != "srv" ] || return ${EC_PLUG_RC_NOTAPPLICABLE}

    fg=$1
    shift
    args=""

    [ -z ${EC_PLUG_CLI_ARG_URI} ] || \
        args="${args} -u ${EC_PLUG_CLI_ARG_URI}${EC_PLUG_CLI_ARG_PATH}"

    [ -z ${EC_PLUG_CLI_ARG_TYPE} ] || \
        args="${args} -M ${EC_PLUG_CLI_ARG_TYPE}"

    [ -z ${EC_PLUG_CLI_ARG_METHOD} ] || \
        args="${args} -m ${EC_PLUG_CLI_ARG_METHOD}"

    [ -z ${EC_PLUG_CLI_ARG_PAYLOAD} ] || \
        args="${args} -p ${EC_PLUG_CLI_ARG_PAYLOAD}"

    [ -z ${EC_PLUG_CLI_ARG_RETRY} ] || \
        args="${args} -r ${EC_PLUG_CLI_ARG_RETRY}"

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

    # upon failure, don't die if killed intentionally (signal) or return code
    # is not applicable
    case $? in ${EC_PLUG_RC_SUCCESS}|\
        ${EC_PLUG_RC_INTERRUPTED}|\
        ${EC_PLUG_RC_NOTAPPLICABLE})
            return 0
            ;;
        *)
            t_dbg 1 "client failed! (rc=$?)"
    esac
}

# Run a CoAP client in background.
t_cli_run_bg()
{
    __t_cli_run 1

    # add pid to list of processes to be killed
    t_pid_add $!

    sleep 1
}

# Set client uri
t_cli_set_uri()
{
    [ -z $1 ] && t_die ${EC_PLUG_RC_BADPARAMS} "URI must be defined!"

    EC_PLUG_CLI_ARG_URI=$1
}

# Set client path
t_cli_set_path()
{
    [ -z $1 ] && t_die ${EC_PLUG_RC_BADPARAMS} "Path must be defined!"

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
            t_die ${EC_PLUG_RC_BADPARAMS} "bad type: ${t}" ;;
    esac
}

# Set client method
t_cli_set_method()
{
    [ -z $1 ] && t_die ${EC_PLUG_RC_BADPARAMS} "Method must be defined!"

    m=$1

    case "${m}" in
        GET|POST|PUT|DELETE)
            EC_PLUG_CLI_ARG_METHOD="${m}" ;;
        *)
            t_die ${EC_PLUG_RC_BADPARAMS} "bad method: ${m}" ;;
    esac
}

# Set client payload
t_cli_set_payload()
{
    [ -z $1 ] && unset EC_PLUG_CLI_ARG_PAYLOAD

    EC_PLUG_CLI_ARG_PAYLOAD=$1
}

# Activate retry upon failure
t_cli_set_retry()
{
    [ -z $1 ] && unset EC_PLUG_CLI_ARG_RETRY

    EC_PLUG_CLI_ARG_RETRY=$1
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
    id=$1
    srv=$2
    field=$3
    dump="${id}-${srv}.dump"

    __t_applicable ${srv} || return ${EC_PLUG_RC_NOTAPPLICABLE}

    t_dbg "retrieving field '${field}' from '${dump}'"

    [ -r "${dump}" ] || return ${EC_PLUG_RC_GENERR}

    # retrieve line
    xval=`grep "${field}:" "${dump}"`
    [  $? -eq 0 ] || return ${EC_PLUG_RC_GENERR}

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

    id=$1
    srv=$2
    field=$3
    val=$4
    dump="${id}-${srv}.dump"

    __t_applicable ${srv} || return ${EC_PLUG_RC_NOTAPPLICABLE}

    [ -r "${dump}" ] || t_die ${EC_PLUG_RC_GENERR} "missing dump: '${dump}'"

    # retrieve line
    xval=`grep "${field}:" "${dump}"`
    [  $? -eq 0 ] || t_die ${EC_PLUG_RC_GENERR} "field '${field}' not found!"

    # retrieve value
    xval=`${ECHO} ${xval} | cut -d ':' -f 2`

    # remove leading space
    xtrim=`${ECHO} ${xval} | sed 's/^ //'`

    t_dbg "checking message ${dump} field '${field}': '${xtrim}'"

    # compare result with value    
    [ "${xtrim}" = "${val}" ] || t_die ${EC_PLUG_RC_GENERR} \
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
    id=$1
    srv=$2
    field=$3
    val=$4
    dump="${id}-${srv}.dump"

    __t_applicable ${srv} || return ${EC_PLUG_RC_NOTAPPLICABLE}

    [ -r "${dump}" ] || t_die ${EC_PLUG_RC_GENERR} "missing dump: '${dump}'"

    # retrieve line
    xval=`grep "${field}:" "${dump}"`
    [  $? -eq 0 ] || return ${EC_PLUG_RC_GENERR}

    # retrieve value
    xval=`${ECHO} ${xval} | cut -d ':' -f 2`

    # remove leading space
    xtrim=`${ECHO} ${xval} | sed 's/^ //'`

    t_dbg "checking message ${dump} field '${field}' != '${xtrim}'"

    # compare result with value    
    [ "${xtrim}" != "${val}" ] || t_die ${EC_PLUG_RC_GENERR} \
            "failed check! (found: '${xtrim}', expected !=)"
}

# Check the size of a string.
#
# $1    input string
# $2    min size of string
# $3    max size of string
t_check_len()
{
    [ "${EC_PLUG_DUMP}" = "1" ] || return ${EC_PLUG_RC_NOTAPPLICABLE}

    s=$1
    min=$2
    max=$3

    t_dbg "checking length of '${s}' (>=${min}, <=${max})"

    xlen=`${ECHO} -n "${s}" | wc -c | sed -e 's/\ //g'`

    [ ${xlen} -ge ${min} ] || t_die ${EC_PLUG_RC_GENERR} "bad length!"
    [ ${xlen} -le ${max} ] || t_die ${EC_PLUG_RC_GENERR} "bad length!"
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
    [ -z $1 ] && t_die ${EC_PLUG_RC_BADPARAMS} "seconds undefined!"
    s=$1
    [ -z "$2" ] && t_die ${EC_PLUG_RC_BADPARAMS} "commands undefined!"

    t_dbg "timer secs: $1"

    shift

    t_dbg "timer cmds: $@"

    __t_timer ${s} "$@" &
}

# Print a message and prompt the user for a keypress to continue test
#
# $@    Message to print before prompt
t_prompt()
{
    if [ "$1" = "" ]; then
        msg="Execute next steps, then press ENTER to continue."
    else
        msg="$@"
    fi

    ${ECHO} "# ${msg}"
    read line
}

# Append to list of PIDS to be killed upon termination
t_pid_add()
{
    EC_PLUG_PIDS="${EC_PLUG_PIDS} $@"
}

trap "t_term ${EC_PLUG_RC_INTERRUPTED}" 2 9 15
