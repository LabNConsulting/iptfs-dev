
ifdef SHALLOW_CLONE
DEPTH ?= --depth 1
endif

all: kernel rootfs tests/trex

setup:
	([ -d buildroot ] || [ -h buildroot ]) || git clone $(DEPTH) git://git.buildroot.net/buildroot buildroot -b 2022.08
	([ -d iproute2 ] || [ -h iproute2 ]) || git clone $(DEPTH) https://github.com/LabNConsulting/iptfs-iproute2.git iproute2 -b iptfs
	([ -d linux ] || [ -h linux ]) || git clone $(DEPTH) https://github.com/LabNConsulting/iptfs-linux.git linux -b iptfs

kernel: output-linux/arch/x86/boot/bzImage

rootfs: output-buildroot/images/rootfs.cpio.gz

# These aren't phoney but we always want to descend to check them with make
.PHONY: output-linux/arch/x86/boot/bzImage output-buildroot/images/rootfs.cpio.gz

linux-menuconfig:
	make -C linux O=../output-linux menuconfig

output-linux/arch/x86/boot/bzImage: output-linux output-linux/.config
	mkdir -p output-linux
	make -C linux -j$(shell nproc) O=../output-linux

output-buildroot/images/rootfs.cpio.gz: output-buildroot output-buildroot/.config
	mkdir -p output-buildroot
	make -C buildroot -j$(shell nproc) V=1 O=../output-buildroot

output-linux/.config: linux.config
	cp -p $< $@

output-buildroot/.config: buildroot.config
	cp -p $< $@

output-buildroot:
	mkdir -p $@

output-linux:
	mkdir -p $@

tests/trex:
	scripts/extract-trex.sh
