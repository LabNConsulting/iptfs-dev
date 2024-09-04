# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# February 9 2022, Christian Hopps <chopps@labn.net>
#
# Copyright 2022, LabN Consulting, L.L.C.
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
"Simple virtual interface qemu based iptfs test."
import logging
import os

import pytest
from common.config import _network_up, setup_policy_tun, setup_routed_tun
from common.tests import _test_net_up

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


async def test_net_up(unet, astepf):
    await astepf("Before test network up")
    await _test_net_up(unet, ipv6=True)


async def do_ping(h1, astepf):
    count = 3000

    await astepf("first IPv6 ping")
    logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))
    await astepf(f"flood {count} IPv6 ping")
    logging.debug(h1.cmd_raises(f"ping -f -c{count} fc00:0:0:2::4"))

    await astepf("first IPv4 ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    await astepf(f"flood {count} IPv4 ping")
    logging.debug(h1.cmd_raises(f"ping -f -c{count} 10.0.2.4"))


async def test_policy_tun4_up(unet, astepf, pytestconfig):
    h1 = unet.hosts["h1"]

    opts = pytestconfig.getoption("--iptfs-opts", "dont-frag")
    await setup_policy_tun(
        unet, mode="iptfs", iptfs_opts=opts, ipv6=True, tun_ipv6=False
    )

    await do_ping(h1, astepf)


async def test_routed_tun4_up(unet, astepf, pytestconfig):
    h1 = unet.hosts["h1"]

    opts = pytestconfig.getoption("--iptfs-opts", "")
    await setup_routed_tun(
        unet, mode="iptfs", iptfs_opts=opts, ipv6=True, tun_ipv6=False
    )

    await do_ping(h1, astepf)


async def test_policy_tun6_up(unet, astepf, pytestconfig):
    h1 = unet.hosts["h1"]

    opts = pytestconfig.getoption("--iptfs-opts", "dont-frag")
    await setup_policy_tun(
        unet, mode="iptfs", iptfs_opts=opts, ipv6=True, tun_ipv6=True
    )

    await do_ping(h1, astepf)


async def test_routed_tun6_up(unet, astepf, pytestconfig):
    h1 = unet.hosts["h1"]

    opts = pytestconfig.getoption("--iptfs-opts", "")
    await setup_routed_tun(
        unet, mode="iptfs", iptfs_opts=opts, ipv6=True, tun_ipv6=True
    )

    await do_ping(h1, astepf)
