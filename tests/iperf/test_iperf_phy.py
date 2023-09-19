# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# January 19 2023, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2023, LabN Consulting, L.L.C.
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
"Test iptfs tunnel using iperf with various configurations"
import os

import pytest
from common.config import _network_up, setup_policy_tun
from common.tests import _test_net_up
from iperf import _test_iperf, check_logs, skip_future
from munet.testing.fixtures import _unet_impl

# All tests are coroutines
pytestmark = pytest.mark.asyncio

SRCDIR = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module", autouse=True)
async def checkrun(pytestconfig):
    if not pytestconfig.option.enable_physical:
        pytest.skip(
            "Physical interface test being skipped, pass --enable-physical",
            allow_module_level=True,
        )


@pytest.fixture(scope="module", name="lcl_unet")
async def _unet(rundir_module, pytestconfig):
    async for x in _unet_impl(rundir_module, pytestconfig, param="munet_phy"):
        yield x


@pytest.fixture(scope="module", autouse=True)
async def network_up(lcl_unet):
    unet = lcl_unet
    await _network_up(unet, ipv6=unet.ipv6_enable)
    unet.hosts["r1"].add_watch_log("qemu.out")
    unet.hosts["r2"].add_watch_log("qemu.out")
    yield


#                       192.168.0.0/24  fd00::/64
#   --+-------------------+------ mgmt0 ------+-------------------+---
#     | .1                | .2                | .3                | .4
#   +----+              +----+              +----+              +----+
#   | h1 | --- net0 --- | r1 | --- net1 --- | r2 | --- net2 --- | r1 |
#   +----+ .1        .2 +----+ .2        .3 +----+ .3        .4 +----+
#          10.0.0.0/24         10.0.1.0/24         10.0.2.0/24
#           fc00::/64         fc00:0:0:1::/64     fc00:0:0:2::/64


async def test_net_up(lcl_unet):
    unet = lcl_unet
    await _test_net_up(unet, ipv6=unet.ipv6_enable)
    check_logs(unet)


MODE = "iptfs"


async def test_tun_up(lcl_unet, astepf):
    unet = lcl_unet
    # iptfs_opts = "dont-frag"
    await setup_policy_tun(
        unet,
        mode=MODE,
        ipsec_intf="eth1",
        iptfs_opts="",
        ipv6=unet.ipv6_enable,
    )

    # h1 = unet.hosts["h1"]
    # r1 = unet.hosts["r1"]

    # await astepf("Before R2R ping")
    # # r1 (qemu side) pings r2 (qemu side)
    # r1.conrepl.cmd_nostatus("ping -w1 -i.2 -c1 10.0.1.3")
    # r1.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.3")

    # await astepf("Before H2H ping")
    # # h1 pings h2
    # h1.cmd_nostatus("ping -w1 -i.2 -c1 10.0.2.4")
    # h1.cmd_raises("ping -w1 -i.2 -c1 10.0.2.4")

    check_logs(unet)


# overrun the queue setup
# @pytest.mark.parametrize(
#     "iptfs_opts", ["pkt-size 256 max-queue-size 100000"], scope="function"
# )
# @pytest.mark.parametrize("pktsize", [8000])
# @pytest.mark.parametrize("ipv6", [False])
# @pytest.mark.parametrize("tun_ipv6", [False])
# @pytest.mark.parametrize("routed", [False])

# @pytest.mark.parametrize("iptfs_opts", ["", "dont-frag"], scope="function")
# @pytest.mark.parametrize("iptfs_opts", ["init-delay 1000"], scope="function")

# @pytest.mark.parametrize("iptfs_opts", [""], scope="function")
# @pytest.mark.parametrize("pktsize", [None, 88, 536, 1442], scope="function")
# @pytest.mark.parametrize("ipv6", [False, True], scope="function")
# @pytest.mark.parametrize("tun_ipv6", [False, True], scope="function")
# @pytest.mark.parametrize("routed", [False, True], scope="function")


# @pytest.mark.parametrize("iptfs_opts", ["init-delay 1000"], scope="function")


@pytest.mark.parametrize("iptfs_opts", [""], scope="function")
@pytest.mark.parametrize("pktsize", [None, 88, 536, 1442], scope="function")
@pytest.mark.parametrize("ipv6", [False, True], scope="function")
@pytest.mark.parametrize("tun_ipv6", [False, True], scope="function")
@pytest.mark.parametrize("routed", [False, True], scope="function")
async def test_iperf(
    lcl_unet, rundir, astepf, pytestconfig, iptfs_opts, pktsize, ipv6, routed, tun_ipv6
):
    unet = lcl_unet
    if skip_future:
        pytest.skip("Skipping test due to earlier failure")

    if not unet.ipv6_enable and tun_ipv6:
        pytest.skip("skipping ipv6 as --enable-ipv6 not specified")
    if ipv6 and pktsize and pktsize < 536:
        pytest.skip("Can't run IPv6 iperf with MSS < 536")
        return

    test_iperf.count += 1

    use_iperf3 = True
    if use_iperf3 and pktsize and pktsize < 88:
        pktsize = 88

    # Leak cases tun_ipv6 = True | False, ipv6 = True
    # Non-Leak cases tun_ipv6 = True | False, ipv6 = False

    result = await _test_iperf(
        unet,
        astepf,
        mode=MODE,
        ipsec_intf="eth1",
        use_iperf3=use_iperf3,
        iptfs_opts=iptfs_opts,
        pktsize=pktsize,
        routed=routed,
        ipv6=ipv6,
        tun_ipv6=tun_ipv6,
        profile=pytestconfig.getoption("--profile", False),
        profcount=test_iperf.count,
        tracing=pytestconfig.getoption("--tracing", False),
        duration=pytestconfig.getoption("--duration", 10.0),
    )
    assert result, "No result from test!"

    fname = rundir[: rundir.rindex("/")] + "/speed-phy.csv"
    fmode = "w+" if test_iperf.count == 0 else "a+"
    tunstr = "routed" if routed else "policy"
    vstr = "IPv6" if tun_ipv6 else "IPv4"
    with open(fname, fmode, encoding="ascii") as f:
        print(
            f"{result[2]}{result[3]}bits/s,{result[1]},{result[0]},{pktsize},{tunstr},{vstr},{iptfs_opts}",
            file=f,
        )


test_iperf.count = -1
