. ../share/common.sh

t_init

t_run_srv

out=`t_run_cli "" "" "" "/test"`
t_dbg "< ${out}"

if [ "${MODE}" = "cli" ]; then
    t_cmp "${out}" "Hello World!"
fi

t_term
