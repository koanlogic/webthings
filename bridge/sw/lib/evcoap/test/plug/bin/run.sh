#!/bin/sh
#
# Simply run all test vectors.

VEC_PATH=../vectors

for v in `ls ${VEC_PATH}`; do

    echo "# test: ${v}"
    sh "${VEC_PATH}/${v}"

    if [ $? = 0 ]; then
        echo "# [ok]."
    else
        echo "# [***KO***]."
    fi
done
