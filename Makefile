LINUXCONFIG ?= linux.config
# LINUXCONFIG ?= linux-cov.config
# LINUXCONFIG ?= linux-fast.config
# LINUXCONFIG ?= linux-fasttrace.config
# LINUXCONFIG ?= linux-nosmp.config

ifdef SHALLOW_CLONE
DEPTH ?= --depth 1
endif

all: kernel rootfs

setup:
	([ -d buildroot ] || [ -h buildroot ]) || git clone $(DEPTH) git://git.buildroot.net/buildroot buildroot -b 2023.05
	([ -d iproute2 ] || [ -h iproute2 ]) || git clone $(DEPTH) https://github.com/LabNConsulting/iptfs-iproute2.git iproute2 -b iptfs
	([ -d linux ] || [ -h linux ]) || git clone $(DEPTH) https://github.com/LabNConsulting/iptfs-linux.git linux -b iptfs

kernel: output-linux/arch/x86/boot/bzImage
# kernel: linux/arch/x86/boot/bzImage

rootfs: output-buildroot/images/rootfs.cpio.gz

# These aren't phoney but we always want to descend to check them with make
# .PHONY: linux/arch/x86/boot/bzImage output-buildroot/images/rootfs.cpio.gz
.PHONY: output-linux/arch/x86/boot/bzImage output-buildroot/images/rootfs.cpio.gz

linux-defconfig:
	make -C linux O=../output-linux defconfig
linux-menuconfig:
	make -C linux O=../output-linux menuconfig

br-defconfig:
	make -C buildroot O=../output-buildroot defconfig

br-menuconfig:
	make -C buildroot O=../output-buildroot menuconfig

output-linux/arch/x86/boot/bzImage: output-linux output-linux/.config
	mkdir -p output-linux
	make -C linux -j$(shell nproc) O=../output-linux
	(cd linux && scripts/clang-tools/gen_compile_commands.py -d../output-linux)

# linux/arch/x86/boot/bzImage: linux/.config
# 	make -C linux -j$(shell nproc)
# 	(cd linux && scripts/clang-tools/gen_compile_commands.py)


output-buildroot/images/rootfs.cpio.gz: output-buildroot output-buildroot/.config
	mkdir -p output-buildroot
	make -C buildroot -j$(shell nproc) V=1 O=../output-buildroot

output-linux/.config: $(LINUXCONFIG)
	cp -p $< $@

output-buildroot/.config: buildroot.config
	cp -p $< $@

output-buildroot:
	mkdir -p $@

output-linux:
	mkdir -p $@

#
# Testing
#
tests/ci:
	sudo -E pytest -s tests/config tests/errors tests/frags tests/simplenet tests/utpkt/test_utpkt.py

tests-trex/external_libs:
	scripts/extract-trex.sh

clean-trex:
	rm -rf tests-trex/podman-trex-extract tests-trex/trex tests-trex/trex_stl_lib tests-trex/external_libs

test: tests-trex/external_libs
	sudo -E pytest -s tests
	sudo -E pytest -s tests-trex

#
# CI Rules
#
ci-extract-cov:
	bash scripts/extract-cov.sh
	mkdir -p test-logs
	cp *.info test-logs

#
# Personal
#
# PERFTEST := tests/stress/test_stress_phy.py::test_policy_small_pkt
# PERFSLAB := tests.stress.test_stress_phy
#PERFFILE := ./res-latest/$(PERFSLAB)/r1/perf-0.data

PERFTEST := tests/iperf/test_iperf_phy.py::test_iperf[False-False-False-88-]
PERFSLAB := tests.iperf.test_iperf_phy
PERFFILE := /tmp/unet-test/$(PERFSLAB)/r1/perf-0.data

flame-clean:
	sudo rm -f /tmp/out.perf-folded flame.svg $(PERFFILE)

flame: flame.svg
	scp flame.svg ja:

$(PERFFILE):
	sudo -E pytest -s -v '$(PERFTEST)' --enable-physical --profile || true

PERF := ../output-buildroot/target/usr/bin/perf

FlameGraph:
	git clone https://github.com/brendangregg/FlameGraph

/tmp/out.perf: FlameGraph $(PERFFILE)
	(cd FlameGraph && $(PERF) script --vmlinux ../output-linux/vmlinux -i $< > /tmp/out.perf)

/tmp/out.perf-folded: FlameGraph /tmp/out.perf
	(cd FlameGraph && cat /tmp/out.perf | ./stackcollapse-perf.pl > /tmp/out.perf-folded)

flame.svg: FlameGraph /tmp/out.perf-folded
	(cd FlameGraph && ./flamegraph.pl --height=16 --fontsize=6 $< > ../$@)

