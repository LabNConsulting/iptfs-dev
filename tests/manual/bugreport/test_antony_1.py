# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# May 24 2024, Christian Hopps <chopps@labn.net>
#
# Copyright 2024, LabN Consulting, L.L.C.
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
"Replicate bug report from Antony Antony."
from pathlib import Path

import pytest
from common.config import _network_up, setup_policy_tun
from common.tests import _test_net_up
from munet.testing.fixtures import _unet_impl

# All tests are coroutines
pytestmark = pytest.mark.asyncio


@pytest.fixture(scope="module", name="unet")
async def _unet(rundir_module, pytestconfig):
    async for x in _unet_impl(rundir_module, pytestconfig, param="munet-antony-1"):
        await _network_up(x, ipv6=x.ipv6_enable)
        x.hosts["r1"].add_watch_log("qemu.out")
        x.hosts["r2"].add_watch_log("qemu.out")

        yield x


#                            192.168.0.0/24
#   --+-------------------+------ mgmt0 ------+-------------------+---
#     | .1                | .2                | .3                | .4
#   +----+              +----+              +----+              +----+
#   | h1 | --- net0 --- | r1 | --- net1 --- | r2 | --- net2 --- | r1 |
#   +----+ .1        .2 +----+ .2        .3 +----+ .3        .4 +----+
#          10.0.0.0/24         10.0.1.0/24         10.0.2.0/24

trpath = Path("/sys/kernel/tracing")
evpath = trpath / "events/iptfs"
tronpath = trpath / "tracing_on"


def enable_tracing(r):
    #
    # Enable tracing
    #
    # afpath = trpath / "available_filter_functions"

    evp = evpath / "enable"
    r.cmd_nostatus(f"echo 1 > {evp}")

    # sfpath = trpath / "set_ftrace_filter"
    # r2.cmd_nostatus(f"grep ^iptfs {afpath} > {sfpath}")
    # ctpath = trpath / "current_tracer"
    # r2.cmd_status(f"echo function > {ctpath}")

    # sfpath = trpath / "set_graph_function"
    # r2.cmd_nostatus(f"grep ^iptfs {afpath} > {sfpath}")
    # ctpath = trpath / "current_tracer"
    # r2.cmd_status(f"echo function_graph > {ctpath}")

    r.cmd_status(f"echo 1 > {tronpath}")


def gather_tracing(unet, r):
    r.conrepl.cmd_status(f"echo 0 > {tronpath}")
    # ur2.cmd_status("gzip -c /sys/kernel/tracing/trace > /tmp/trace.gz")
    trfile = unet.rundir.joinpath(f"{r.name}-trace.txt")
    with open(trfile, "w+", encoding="ascii") as f:
        r.cmd_status("cat /sys/kernel/tracing/trace", stdout=f)


async def test_recreate_bug(unet, astepf, pytestconfig):
    ipv6 = pytestconfig.getoption("--enable-ipv6", False)
    iptfs_opts = pytestconfig.getoption("--iptfs-opts", "")
    assert not ipv6 or unet.ipv6_enable

    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]

    enable_tracing(r1)
    enable_tracing(r2)

    await astepf("Before test network up")

    # await _test_net_up(unet, ipv6=ipv6)
    await setup_policy_tun(unet, mode="iptfs", iptfs_opts=iptfs_opts, ipv6=ipv6)

    if False:
        # Doesn't hit
        # r1.cmd_raises("ping -n -c2 -W1 10.0.1.3")
        # Hits
        r1.cmd_raises("ping -n -c2 -W1 -I 10.0.0.2 -s 2000 10.0.1.3")
        # Hits
        # r1.cmd_raises("ping -n -c2 -W1 -s 2000 -I 10.0.0.2 10.0.1.3")
        # Hits
        # r1.cmd_raises("ping -n -c2 -W1 -s 2000 -I 10.0.0.2 10.0.2.3")
    else:
        h1 = unet.hosts["h1"]
        await astepf("Setting large MTU on net0")
        await astepf("Large ping from h1")
        print(h1.cmd_raises("echo H1: && ip -o link && ip -o route"))
        print(r1.cmd_raises("echo R1: && ip -o link && ip -o route"))
        h1.cmd_raises("ping -n -Mdo -c2 -s 2000 10.0.1.3")

    gather_tracing(unet, r1)
    gather_tracing(unet, r2)
