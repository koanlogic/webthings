#!/bin/sh
#
# Simply run all test vectors.

VEC_PATH=../vectors

. ../share/common.sh

echo "#"
echo "# running plugtests v"`cat ../VERSION`"."
echo "#"

for v in `ls "${VEC_PATH}"`; do

    f="${VEC_PATH}/${v}"

    # Match test case prefix.
    echo "${f}" | grep "TD_COAP_" >/dev/null
    [ $? -eq 0 ] || continue

    # Run test.
    desc=`grep "## description: " "${f}" | cut -d ':' -f 2`
    echo "# [test] ${v}:${desc}."
    sh "${f}"

    # Prit exit status.
    if [ $? -eq 0 ]; then
        t_dbg "# [ok]."
    else
        echo "# [***KO***]."
    fi
done
