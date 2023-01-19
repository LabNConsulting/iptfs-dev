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
from common.tests import _test_net_up
from iperf import _test_iperf

# All tests are coroutines
pytestmark = pytest.mark.asyncio

SRCDIR = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module", autouse=True)
async def network_up(unet):
    await _network_up(unet, ipv6=True)


#                       192.168.0.0/24  fd00::/64
#   --+-------------------+------ mgmt0 ------+-------------------+---
#     | .1                | .2                | .3                | .4
#   +----+              +----+              +----+              +----+
#   | h1 | --- net0 --- | r1 | --- net1 --- | r2 | --- net2 --- | r1 |
#   +----+ .1        .2 +----+ .2        .3 +----+ .3        .4 +----+
#          10.0.0.0/24         10.0.1.0/24         10.0.2.0/24


async def test_net_up(unet):
    await _test_net_up(unet, ipv6=True)


@pytest.mark.parametrize("iptfs_opts", ["", "dont-frag"])
@pytest.mark.parametrize("pktsize", [None, 64, 536, 1442])
@pytest.mark.parametrize("ipv6", [False, True])
@pytest.mark.parametrize("routed", [False, True])
async def test_iperf(unet, astepf, pytestconfig, iptfs_opts, pktsize, routed, ipv6):
    if ipv6 and pktsize and pktsize < 536:
        pytest.skip("Can't run IPv6 iperf with MSS < 536")
        return

    test_iperf.count += 1

    await _test_iperf(
        unet,
        astepf,
        "eth2",
        iptfs_opts=iptfs_opts,
        pktsize=pktsize,
        routed=routed,
        ipv6=ipv6,
        profile=pytestconfig.getoption("--profile", False),
        profcount=test_iperf.count,
    )


test_iperf.count = -1
