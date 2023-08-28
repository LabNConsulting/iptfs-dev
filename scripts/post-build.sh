#!/bin/bash
#
# January 21 2022, Christian Hopps <chopps@labn.net>
#
# Copyright 2022, LabN Consulting, L.L.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This is a buildroot ~BR2_ROOTFS_POST_BUILD_SCRIPT~ script.
#
# Environment:
#  BR2_CONFIG: the path to the Buildroot .config file
#  HOST_DIR, STAGING_DIR, TARGET_DIR: see Section 18.5.2, "generic-package reference"
#  BUILD_DIR: the directory where packages are extracted and built
#  BINARIES_DIR: the place where all binary files (aka images) are stored
#  BASE_DIR: the base output directory

# CWD - buildroot root directory
TARGET=$1; shift

ifile=$TARGET/etc/inittab

echo "$0: enabling 4 serial console gettys"
for ((i=0; i<4; i++)); do
    if ! grep "#SERCON$i" $ifile &> /dev/null; then
        if (( i >= 2 )); then
            echo "ttyS$i::respawn:/sbin/getty -n -l /bin/sh -L ttyS$i 115200 vt100 #SERCON$i" >> $ifile
        else
            echo "ttyS$i::respawn:/sbin/getty -L ttyS$i 115200 vt100 #SERCON$i" >> $ifile
        fi
    else
        if (( i >= 2 )); then
            sed -i -e "/#SERCON$i/c\\ttyS$i::respawn:/sbin/getty -n -l /bin/sh -L ttyS$i 115200 vt100 #SERCON$i" $ifile
        else
            sed -i -e "/#SERCON$i/c\\ttyS$i::respawn:/sbin/getty -L ttyS$i 115200 vt100 #SERCON$i" $ifile
        fi
    fi
done

echo "$0: enabling 2 password-less virtual console gettys"
for ((i=0; i<2; i++)); do
    if ! grep "#VIRTCON$i" $ifile &> /dev/null; then
        echo "hvc$i::respawn:/sbin/getty -n -l /bin/sh -L hvc$i 0 vt100 #VIRTCON$i" >> $ifile
    else
        sed -i -e "/#VIRTCON$i/c\\hvc$i::respawn:/sbin/getty -n -l /bin/sh -L hvc$i 0 vt100 #SERCON$i" $ifile
    fi
done

fstab=$TARGET/etc/fstab

if ! grep "debugfs" $fstab; then
    echo "$0: adding debugfs to /etc/fstab"
    echo "debugfs         /sys/kernel/debug       debugfs defaults 0 0" >> $fstab
fi

if ! grep "tracefs" $fstab; then
    echo "$0: adding tracefs to /etc/fstab"
    echo "tracefs         /sys/kernel/tracing       tracefs defaults 0 0" >> $fstab
fi

echo "$0: copying root-key.pub in post-build script."
mkdir -p $TARGET/root/.ssh
if [[ ! -e ../root-key.pub ]]; then
    ssh-keygen -q -t rsa -b 2048 -N "" -f ../root-key
fi
cp ../root-key.pub $TARGET/root/.ssh/authorized_keys
chmod -R =0000,u=rwX $TARGET/root/.ssh

# echo 'PS1="XXPROMPTXX$ "' > $TARGET/etc/profile.d/promptprefix.sh
# rm -f $TARGET/etc/profile.d/promptprefix.sh


chlogf=$TARGET/etc/strongswan.d/charon-logging.conf
if [ -e $chlogf ]; then
    cat <<EOF > $TARGET/etc/strongswan.d/charon-logging.conf
charon {
    filelog {
        debug-log {
            path = "/tmp/charon-debug.log"
            time_format = %b %e %T
            ike_name = yes
            default = 1
            flush_line = yes

            ike = 3
            net = 4
            cfg = 1
            lib = 4
            knl = 4
        }
    }
    syslog {
        identifier = charon-custom
        daemon {
        }
        auth {
            default = -1
            ike = 0
        }
    }
}
EOF
    fi
