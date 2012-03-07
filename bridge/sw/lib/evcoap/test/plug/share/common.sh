#VERBOSE=1
SRV_ADDR="coap://[::1]:5683"
CLI_CMD="../../client/coap-client"
SRV_CMD="../server/coap-server"

[ "${DUMP_PDUS}" = "1" ] || \
        echo "# [warn] DUMP_PDUS not set,"\
             "no 'check' steps will be performed"


# If VERBOSE=1, debugs all strings to standard error.
t_dbg()
{
    [ "${VERBOSE}" = "1" ] && echo $@ 1>&2
}

# Print a message and exit with return code $1.
t_die()
{
    rc=$1
    shift
    echo "$@"
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
# $1    method      <GET|POST|PUT|DELETE>   (default is GET)
# $2    message     <CON|NON>               (default is CON)
# $3    address     <uri>                   (default is coap://[::1])
# $4    resource    <rsrc>                  (default is /test)
#
t_run_cli()
{
    [ "${MODE}" != "srv" ] || return 0

    meth=$1
    msg=$2
    addr=$3
    rsrc=$4

    # set defaults for empty string vals
    [ "${meth}" = "" ] && meth="GET"
    [ -z ${msg} ] && msg="CON"
    [ -z ${addr} ] && addr="${SRV_ADDR}"
    [ -z ${rsrc} ] && rsrc="/test"

    t_wrap 0 "${CLI_CMD}" -m "${meth}" -M "${msg}" -u "${addr}${rsrc}" -o -
    [ $? -eq 0 ] || t_die 1 "client failed! (rc=$?)"
}

# Get the value of a field in header.
#
# $1    packet identifier
# $2    srv|cli
# $3    field name
t_get_hdr()
{
    [ "${DUMP_PDUS}" = "1" ] || return

    id=$1
    srv=$2
    field=$3

    grep ${field}= ${id}-${srv}.dump | cut -d '=' -f 2
}

# Check the value of a dumped header.
#
# $1    packet identifier
# $2    srv|cli
# $3    field name
# $4    field value
t_check_hdr()
{
    [ "${DUMP_PDUS}" = "1" ] || return

    id=$1
    srv=$2
    field=$3
    val=$4

    t_dbg "# checking message ${id}-${srv} field ${field} val ${val}"

    xval=`grep ${field}= ${id}-${srv}.dump | cut -d '=' -f 2`
    [ "${xval}" = "${val}" ] || t_die 1 "failed check! (rc=$?)"
}

trap t_term 2 9 15
