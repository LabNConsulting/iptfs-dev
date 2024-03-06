LINUXCONFIG ?= linux.config
# LINUXCONFIG ?= linux-cov.config
# LINUXCONFIG ?= linux-fast.config
# LINUXCONFIG ?= linux-fasttrace.config
# LINUXCONFIG ?= linux-nosmp.config

ifdef SHALLOW_CLONE
DEPTH ?= --depth 1
endif

all: kernel rootfs iperf

setup:
	([ -d buildroot ] || [ -h buildroot ]) || git clone $(DEPTH) git://git.buildroot.net/buildroot buildroot -b 2023.11.1
	([ -d iproute2 ] || [ -h iproute2 ]) || git clone $(DEPTH) https://github.com/LabNConsulting/iptfs-iproute2.git iproute2 -b iptfs
	([ -d linux ] || [ -h linux ]) || git clone $(DEPTH) https://github.com/LabNConsulting/iptfs-linux.git linux -b iptfs

kernel: output-linux/arch/x86/boot/bzImage

kernel-warn: output-linux/arch/x86/boot/bzImage
	mkdir -p output-linux
	make -C linux -j$(shell nproc) V=1 C=1 W=1 O=../output-linux LOCALVERSION='' 2>&1 | tee warn-log.txt

# kernel: linux/arch/x86/boot/bzImage

rootfs: output-buildroot/images/rootfs.cpio.gz

# These aren't phoney but we always want to descend to check them with make
# .PHONY: linux/arch/x86/boot/bzImage output-buildroot/images/rootfs.cpio.gz
.PHONY: output-linux/arch/x86/boot/bzImage output-buildroot/images/rootfs.cpio.gz

linux-defconfig:
	make -C linux O=../output-linux defconfig
linux-menuconfig:
	make -C linux O=../output-linux menuconfig
linux-allyesconfig:
	make -C linux O=../output-linux allyesconfig
linux-allmodconfig:
	make -C linux O=../output-linux allmodconfig

br-defconfig:
	make -C buildroot O=../output-buildroot defconfig

br-menuconfig:
	make -C buildroot O=../output-buildroot menuconfig

output-linux/arch/x86/boot/bzImage: output-linux output-linux/.config
	mkdir -p output-linux
	make -C linux -j$(shell nproc) O=../output-linux LOCALVERSION=''
	(cd linux && scripts/clang-tools/gen_compile_commands.py -d../output-linux)

# linux/arch/x86/boot/bzImage: linux/.config
# 	make -C linux -j$(shell nproc)
# 	(cd linux && scripts/clang-tools/gen_compile_commands.py)


output-buildroot/images/rootfs.cpio.gz: output-buildroot output-buildroot/.config
	mkdir -p output-buildroot
	make -C buildroot -j$(shell nproc) V=1 O=../output-buildroot LOCALVERSION=''

output-linux/.config: $(LINUXCONFIG)
	cp -p $< $@

output-buildroot/.config: buildroot.config
	cp -p $< $@

output-buildroot output-iperf3 output-linux:
	mkdir -p $@

# local iperf

iperf: iperf3 output-iperf3/src/iperf3

iperf3:
	([ -d iperf ] || [ -h iperf ]) || git clone $(DEPTH) https://github.com/LabNConsulting/iperf.git iperf3 -b imix
	(cd iperf3 && git pull --rebase)

iperf3/configure: iperf3/configure.ac
	(cd iperf3 && ./bootstrap.sh)

output-iperf3/Makefile: iperf3/configure
	mkdir -p output-iperf3
	(cd output-iperf3 && ../iperf3/configure --enable-static-bin)

output-iperf3/src/iperf3: output-iperf3/Makefile
	(cd output-iperf3 && make -j$(nproc))

#
# Testing
#
tests/ci: iperf
	sudo -E pytest -s tests/config tests/errors tests/frags tests/simplenet tests/utpkt/test_utpkt.py

tests-trex/external_libs:
	scripts/extract-trex.sh

clean-trex:
	rm -rf tests-trex/podman-trex-extract tests-trex/trex tests-trex/trex_stl_lib tests-trex/external_libs

test: iperf tests-trex/external_libs
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

# PERFTEST := tests/iperf/test_iperf_phy.py::test_iperf[False-False-False-88-]
# PERFSLAB := tests.iperf.test_iperf_phy

PERFTEST := tests/iperf/test_iperf_phy.py::test_iperf[False-False-False-None-]

PERFSLAB := $(subst /,.,$(shell SLAB=$(PERFTEST); echo $${SLAB%.py*}))

PERFPFX := /tmp/unet-test/$(PERFSLAB)
PERFFILES := $(PERFPFX)/r1/perf-0.data $(PERFPFX)/r2/perf-0.data

PERFBIN := ../output-buildroot/target/usr/bin/perf

flame-clean:
	sudo rm -f $(PERFPFX)/perf-*.data $(PERFPFX)/perf-*.fdata flame-r1.svg flame-r2.svg $(PERFFILES)

flame: iperf flame-r1.svg flame-r2.svg
	scp flame.svg ja:

$(PERFFILES):
	sudo -E pytest -s -v '$(PERFTEST)' --enable-physical --profile || true

FlameGraph:
	git clone https://github.com/brendangregg/FlameGraph

$(PERFPFX)/perf-%.data: $(PERFPFX)/%/perf-0.data
	sudo chown $(USER) $(PERFPFX)
	(cd FlameGraph && $(PERFBIN) script --vmlinux ../output-linux/vmlinux -i $< > $@)

$(PERFPFX)/perf-%.fdata: $(PERFPFX)/perf-%.data
	sudo chown $(USER) $(PERFPFX)
	(cd FlameGraph && ./stackcollapse-perf.pl $< > $@)

flame-%.svg: $(PERFPFX)/perf-%.fdata
	(cd FlameGraph && ./flamegraph.pl --height=16 --fontsize=6 $< > ../$@)


#
# Making and sending patches
#
#
# git format-patch -v2 --subject-prefix="RFC ipsec-next" -o ../patches/v2/ upstream/master..HEAD
# git send-email --cc='Steffen Klassert <steffen.klassert@secunet.com>' \
#   --cc='netdev@vger.kernel.org' --to='devel@linux-ipsec.org' \
#   --cc='chopps@chopps.org' ../patches/v2 \
#
