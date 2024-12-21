#!/bin/bash
#
# November 12 2023, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2023, LabN Consulting, L.L.C.
#
#
if [ -z $SHA ]; then
    echo "SHA variable must be set"
    exit 1
fi

set -e

if [[ -z $TEST_OUTPUT_DIR ]]; then
    outdir=./output-test
else
    outdir=$TEST_OUTPUT_DIR
fi
if [[ -d $outdir ]]; then
    echo "=== Removing $outdir"
    rm -rf $outdir
fi

echo "=== Building allyesconfig"
make O=$outdir -j $(nproc) allyesconfig all > /tmp/$USER-allyesconfig-$SHA.txt 2>&1
echo "=== Success"

echo "=== Removing $outdir"
rm -rf $outdir

echo "=== Building allmodconfig"
make O=$outdir -j $(nproc) allmodconfig all > /tmp/$USER-allmodconfig-$SHA.txt 2>&1
echo "=== Success"

echo "=== Success building with $SHA"

set +e
exit 0
