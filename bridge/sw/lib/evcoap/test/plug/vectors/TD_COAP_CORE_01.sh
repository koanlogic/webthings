. ../share/common.sh

t_init
t_run_srv
out=`t_run_cli "" "" "" "/test"`
t_cmp "${out}" "Hello World!"
t_term
