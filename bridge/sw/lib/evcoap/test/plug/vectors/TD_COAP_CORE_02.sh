. ../share/common.sh

t_init

t_run_srv

out=`t_run_cli "POST" "CON" "" "/test"`
t_dbg "< ${out}"

t_check_hdr 1 "srv" "h_type" 0
#t_check_hdr 1 "srv" "h_code" 2

t_check_hdr 1 "cli" "h_code" 65
v=`t_get_hdr 1 "srv" "h_mid"`
t_check_hdr 1 "cli" "h_mid" ${v}

t_term
