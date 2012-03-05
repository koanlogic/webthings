. ../share/common.sh

t_init

t_run_srv

out=`t_run_cli "PUT" "NON" "" "/test"`
t_dbg "< ${out}"

t_term
