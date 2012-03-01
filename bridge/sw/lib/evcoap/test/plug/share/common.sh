#VERBOSE=1
SRV_ADDR=coap://[::1]/
CLI_CMD=../../client/coap-client
SRV_CMD=../server/coap-server

t_dbg()
{
    [ "${VERBOSE}" = "1" ] && echo $@
}

t_die()
{
    rc=$1
    shift
    echo "$@"
    t_term
    exit ${rc}
}

t_cmp()
{
    if [ "$1" = "$2" ]; then
        return 0
    else 
        t_die 1 "[KO] comparison failed! ($1,$2)"
    fi
}

t_init()
{
    return 0
}

t_term()
{
    kill `jobs -p` 2>/dev/null
}

t_run_srv()
{
    ${SRV_CMD} &
}

#
# $1    method      <GET|POST|PUT|DELETE>   (default is GET)
# $2    message     <CON|NON>               (default is CON)
# $3    address     <uri>                   (default is coap://[::1])
# $4    resource    <rsrc>                  (default is /test)
#
t_run_cli()
{
    meth=$1
    msg=$2
    addr=$3
    rsrc=$4

    # set defaults for empty string vals
    [ "${meth}" = "" ] && meth="GET"
    [ -z ${msg} ] && msg="CON"
    [ -z ${addr} ] && addr="coap://[::1]"
    [ -z ${rsrc} ] && rsrc="/test"

    ${CLI_CMD} -m ${meth} -M ${msg} -u ${addr}/${rsrc} -o - 2>/dev/null
}

trap t_term 2 9 15
