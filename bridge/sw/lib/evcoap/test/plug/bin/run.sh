#!/bin/sh
#
# Simply run all test vectors.

VEC_PATH=../vectors

for v in `ls ${VEC_PATH}`; do
    echo "# test: ${v}"
    sh "${VEC_PATH}/${v}"
    [ $? = 0 ] && echo "# [ok]."
done
