. ../share/common.sh

t_init

t_run_srv

out=`t_run_cli "DELETE" "CON" "" "/test"`
t_dbg "< ${out}"

t_term
