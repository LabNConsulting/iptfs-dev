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
from common.config import _network_up
from iperf import _test_iperf, skip_future
from munet.testing.fixtures import _unet_impl

# All tests are coroutines
pytestmark = pytest.mark.asyncio

SRCDIR = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module", name="unet")
async def _unet(rundir_module, pytestconfig):
    async for x in _unet_impl(rundir_module, pytestconfig):
        await _network_up(x, ipv6=True)
        x.hosts["r1"].add_watch_log("qemu.out")
        x.hosts["r2"].add_watch_log("qemu.out")
        yield x


#                       192.168.0.0/24  fd00::/64
#   --+-------------------+------ mgmt0 ------+-------------------+---
#     | .1                | .2                | .3                | .4
#   +----+              +----+              +----+              +----+
#   | h1 | --- net0 --- | r1 | --- net1 --- | r2 | --- net2 --- | r1 |
#   +----+ .1        .2 +----+ .2        .3 +----+ .3        .4 +----+
#          10.0.0.0/24         10.0.1.0/24         10.0.2.0/24


@pytest.mark.parametrize("mode", ["iptfs", "tunnel"])
@pytest.mark.parametrize("iptfs_opts", [None])
@pytest.mark.parametrize("pktsize", [None, 88, 256, 536, 1442])
@pytest.mark.parametrize("inner", ["ipv4", "ipv6"])
@pytest.mark.parametrize("encap", ["encap4", "encap6"])
@pytest.mark.parametrize("routed", ["policy", "routed"])
async def test_iperf(
    unet, astepf, pytestconfig, mode, iptfs_opts, pktsize, inner, encap, routed
):

    if iptfs_opts is None:
        iptfs_opts = ""
    ipv6 = inner == "ipv6"
    tun_ipv6 = encap == "encap6"
    routed = routed == "routed"

    if skip_future:
        pytest.skip("Skipping test due to earlier failure")

    if mode == "tunnel" and ((not ipv6) != (not tun_ipv6)):
        pytest.skip("Skipping std ipsec test with mixed modes")

    test_iperf.count += 1

    use_iperf3 = True
    if use_iperf3 and pktsize and pktsize < 88:
        pktsize = 88

    result = await _test_iperf(
        unet,
        astepf,
        mode=mode,
        ipsec_intf="eth2",
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

    rundir = str(unet.rundir)
    fname = rundir[: rundir.rindex("/")] + "/speed.csv"
    fmode = "w+" if test_iperf.count == 0 else "a+"
    tunstr = "routed" if routed else "policy"
    vstr = "IPv6" if tun_ipv6 else "IPv4"
    with open(fname, fmode, encoding="ascii") as f:
        print(
            f"{result[2]}{result[3]}bits/s,{result[1]},{result[0]},{pktsize},{tunstr},{vstr},{iptfs_opts}",
            file=f,
        )


test_iperf.count = -1
