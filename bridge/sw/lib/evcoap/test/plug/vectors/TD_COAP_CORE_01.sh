. ../share/common.sh

t_init

t_run_srv

out=`t_run_cli "GET" "CON" "" "/test"`
t_dbg "< ${out}"

if [ "${MODE}" != "srv" ]; then
    t_cmp "${out}" "Hello world!"
fi

t_term
