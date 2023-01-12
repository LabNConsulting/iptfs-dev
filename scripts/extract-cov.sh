#!/bin/bash

tmpdir=$(mktemp -d)-cov
mkdir -p $tmpdir
for f in $(find /tmp/unet-test -name 'gcov-data.tgz'); do
    gzip -dc $f | sudo tar -C $tmpdir -xf -
done
# mkdir -p test-logs
sudo lcov --directory $tmpdir --capture --output-file coverage.info
sudo lcov --extract coverage.info '*xfrm_iptfs*' --output-file iptfs.info

sudo rm -rf $tmpdir
