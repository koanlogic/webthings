#!/bin/sh
#
# Simply run all test vectors.

VEC_PATH=../vectors

echo "#"
echo "# running plugtests v"`cat ../VERSION`"."
echo "#"

for v in `ls "${VEC_PATH}"`; do

    f="${VEC_PATH}/${v}"

    # Match test case prefix.
    echo "${f}" | grep "TD_COAP_" >/dev/null
    [ $? -eq 0 ] || continue

    # Run test.
    echo "# [test] ${v}"
    sh "${f}"

    # Prit exit status.
    if [ $? = 0 ]; then
        echo "# [ok]."
    else
        echo "# [***KO***]."
    fi
done
