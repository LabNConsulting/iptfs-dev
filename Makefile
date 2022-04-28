
all: kernel rootfs tests/trex

setup:
	([ -d buildroot ] || [ -h buildroot ]) || git clone git://git.buildroot.net/buildroot buildroot
	([ -d iproute2 ] || [ -h iproute2 ]) || git clone https://github.com/LabNConsulting/iptfs-iproute2.git iproute2 -b iptfs
	([ -d linux ] || [ -h linux ]) || git clone https://github.com/LabNConsulting/iptfs-linux.git linux -b iptfs

kernel: arch/x86/boot/bzImage

rootfs: buildroot/output/images/rootfs.ext2

# These aren't phoney but we always want to descend to check them with make
.PHONY: arch/x86/boot/bzImage buildroot/output/images/rootfs.ext2

arch/x86/boot/bzImage:
	make -C linux -j$(shell nproc)

buildroot/output/images/rootfs.ext2:
	make -C buildroot -j$(shell nproc)

tests/trex:
	scripts/extract-trex.sh
