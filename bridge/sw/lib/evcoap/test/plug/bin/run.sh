#!/bin/sh
#
# Simply run all test vectors.

V_PATH=../vectors

. ../share/common.sh

echo "#"
echo "# running plugtests v"`cat ../VERSION`"."
echo "#"

vecs="${V_PATH}/TD_COAP_CORE_*.sh"
vecs="${vecs} ${V_PATH}/TD_COAP_LINK_*.sh"
vecs="${vecs} ${V_PATH}/TD_COAP_BLOCK_*.sh"
#vecs="${vecs} ${V_PATH}/TD_COAP_OBS_*.sh"

for v in ${vecs}; do

    f="${V_PATH}/${v}"

    # Run test.
    desc=`grep "## description: " "${f}" | cut -d ':' -f 2`
    echo "# [test] ${v}:${desc}."
    sh "${f}"

    # Print exit status.
    if [ $? -eq 0 ]; then
        t_dbg "# [ok]."
    else
        echo "# [***KO***]."
    fi
done
