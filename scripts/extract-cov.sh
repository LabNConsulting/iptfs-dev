#!/bin/bash
#
# This should be run from the work directory
# export PDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && cd -P .. && pwd )"
# pathcomp=(${PDIR//\// })
# strip=$((${#pathcomp} + 4))
strip=4

tmpdir=$(mktemp -d)-cov
mkdir -p $tmpdir
count=0
for f in $(find /tmp/unet-test -name 'gcov-data.tgz'); do
    ntmpdir=$tmpdir/$count
    mkdir -p $ntmpdir
    echo extracting resutls from $f to $ntmpdir
    gzip -dc $f | tar --strip-components=${strip} -C $ntmpdir -xvf -
    count=$(($count + 1))
done
sudo chown -R $USER $tmpdir

lcov --directory $tmpdir --capture --output-file coverage.info
lcov --extract coverage.info '*xfrm_iptfs*' --output-file iptfs.info
rm -rf $tmpdir
