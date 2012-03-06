. ../share/common.sh

t_init

t_run_srv

out=`t_run_cli "GET" "CON" "" "/test"`
t_dbg "< ${out}"

if [ "${MODE}" != "srv" ]; then
    t_cmp "${out}" "Hello world!"
fi

t_check_hdr 1 "srv" "h_type" 0
t_check_hdr 1 "srv" "h_code" 1

t_check_hdr 1 "cli" "h_code" 69
v=`t_get_hdr 1 "srv" "h_mid"`
t_check_hdr 1 "cli" "h_mid" ${v}

t_term
