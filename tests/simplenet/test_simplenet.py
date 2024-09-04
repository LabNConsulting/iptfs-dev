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
from common.config import _network_up, get_sa_values, setup_policy_tun, setup_routed_tun
from common.tests import _test_net_up

# All tests are coroutines
pytestmark = pytest.mark.asyncio

SRCDIR = os.path.dirname(os.path.abspath(__file__))

# pytestmark = pytest.mark.parametrize(
#     "unet", [("munet", False, False)], indirect=["unet"]
# )


@pytest.fixture(scope="module", autouse=True)
async def network_up(unet, pytestconfig):
    ipv6 = pytestconfig.getoption("--enable-ipv6", False)

    await _network_up(unet, ipv6=ipv6)


#                       192.168.0.0/24  fd00::/64
#   --+-------------------+------ mgmt0 ------+-------------------+---
#     | .1                | .2                | .3                | .4
#   +----+              +----+              +----+              +----+
#   | h1 | --- net0 --- | r1 | --- net1 --- | r2 | --- net2 --- | r1 |
#   +----+ .1        .2 +----+ .2        .3 +----+ .3        .4 +----+
#          10.0.0.0/24         10.0.1.0/24         10.0.2.0/24


async def test_net_up(unet, astepf, pytestconfig):
    ipv6 = pytestconfig.getoption("--enable-ipv6", False)

    await astepf("Before test network up")
    await _test_net_up(unet, ipv6=ipv6)


async def test_policy_tun4_up(unet, astepf, pytestconfig):
    h1 = unet.hosts["h1"]

    ipv6 = pytestconfig.getoption("--enable-ipv6", False)
    opts = pytestconfig.getoption("--iptfs-opts", "")
    await setup_policy_tun(
        unet, mode="iptfs", iptfs_opts=opts, tun_ipv6=False, ipv6=ipv6
    )

    if ipv6:
        await astepf("first IPv6 ping")
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))
        await astepf("second IPv6 ping")
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))
        await astepf("third IPv6 ping")
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))

    # Need to count ESP packets somehow to verify these were encrypted
    await astepf("first ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    await astepf("second ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    await astepf("third ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))


async def test_routed_tun4_up(unet, astepf, pytestconfig):
    h1 = unet.hosts["h1"]

    ipv6 = pytestconfig.getoption("--enable-ipv6", False)
    opts = pytestconfig.getoption("--iptfs-opts", "")
    await setup_routed_tun(unet, iptfs_opts=opts, tun_ipv6=False, ipv6=ipv6)

    if ipv6:
        await astepf("first IPv6 ping")
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))
        await astepf("second IPv6 ping")
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))
        await astepf("third IPv6 ping")
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))

    # Need to count ESP packets somehow to verify these were encrypted
    await astepf("first ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    await astepf("second ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    await astepf("third ping")
    logging.debug(h1.cmd_raises("ping -c3 10.0.2.4"))


async def test_policy_tun6_up(unet, astepf, pytestconfig):
    h1 = unet.hosts["h1"]

    ipv6 = pytestconfig.getoption("--enable-ipv6", False)
    if not ipv6:
        pytest.skip("IPv6 not enabled (--enable-ipv6 to enalbe)")

    opts = pytestconfig.getoption("--iptfs-opts", "")
    await setup_policy_tun(
        unet, mode="iptfs", iptfs_opts=opts, tun_ipv6=True, ipv6=ipv6
    )

    if ipv6:
        await astepf("first IPv6 ping")
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))
        await astepf("second IPv6 ping")
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))
        await astepf("third IPv6 ping")
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))

    # Need to count ESP packets somehow to verify these were encrypted
    await astepf("first ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    await astepf("second ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    await astepf("third ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))


async def test_routed_tun6_up(unet, astepf, pytestconfig):
    h1 = unet.hosts["h1"]

    ipv6 = pytestconfig.getoption("--enable-ipv6", False)
    if not ipv6:
        pytest.skip("IPv6 not enabled (--enable-ipv6 to enalbe)")

    opts = pytestconfig.getoption("--iptfs-opts", "")
    await setup_routed_tun(unet, iptfs_opts=opts, tun_ipv6=True, ipv6=ipv6)

    if ipv6:
        await astepf("first IPv6 ping")
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))
        await astepf("second IPv6 ping")
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))
        await astepf("third IPv6 ping")
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))

    # Need to count ESP packets somehow to verify these were encrypted
    await astepf("first ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    await astepf("second ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    await astepf("third ping")
    logging.debug(h1.cmd_raises("ping -c3 10.0.2.4"))
