#!/bin/bash
host=${1:-r1}
exec sudo socat /dev/stdin,rawer,escape=0x1d,,echo=0,icanon=0 unix-connect:/tmp/unet-root/$host/s/console2

# Inside the namespace
# socat /dev/stdin,rawer,escape=0x1d,,echo=0,icanon=0 unix-connect:/tmp/qemu-sock/console2
