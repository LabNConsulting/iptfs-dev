#!/bin/bash
#
# Copyright (c) 2022, LabN Consulting, L.L.C.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; see the file COPYING; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
#
export LTFSDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && cd .. && pwd )"
export TESTSDIR=$LTFSDIR/tests

CID=""

handler () {
    if [[ $CID ]]; then
        podman stop $CID
        podman rm $CID
    fi
}

trap handler EXIT

if [[ $1 ]]; then
    extract_dir=$1
    SUDO=
else
    extract_dir=$TESTSDIR/podman-trex-extract
fi

# else
#     extract_dir=/opt/trex
#     SUDO=sudo
# fi


trex_image=$(sed -e '/image: quay.io\/labn\/trex.*/!d;s/.*image: *//' $TESTSDIR/stress/munet.yaml)
trex_version=${trex_image#*trex:}
tdir=$extract_dir/$trex_version
libdir=$tdir/automation/trex_control_plane/interactive

symlink1=$TESTSDIR/trex_stl_lib
symlink2=$TESTSDIR/trex

for symdir in trex trex_stl_lib; do
    symlink=$AUTOVPP/$symdir
    if [[ -h $symlink ]]; then
        if [[ "$(realpath $symlink)" == "$(realpath $libdir/$symdir)" ]]; then
            exit 0
        fi
        echo "Symlink to wrong version will extract and update"
    elif [[ -e $symlink ]]; then
        echo "$symlink not a symlink"
        exit 1
    fi
done

if [[ ! -e $tdir ]]; then
    CID=$(podman create ${trex_image})
    $SUDO mkdir -p $extract_dir
    $SUDO podman cp $CID:/trex $tdir
else
    echo "$tdir already exists"
fi

echo "== Creating/Updating symlinks to trex libraries"
# $SUDO ln -fs $libdir/trex $autovpp/
for symdir in trex trex_stl_lib; do
    symlink=$TESTSDIR/$symdir
    set -x
    ln -fs $libdir/$symdir $symlink
    set +x
done
