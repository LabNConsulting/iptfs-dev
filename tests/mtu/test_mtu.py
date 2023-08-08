# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# August 12 2023, Christian Hopps <chopps@labn.net>
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
"Test various MTU configurations are handled correctly."
import asyncio
import logging
import os

import pytest
from common.config import (
    _network_up3,
    setup_policy_tun,
    setup_routed_tun,
    toggle_forward_pmtu,
)
from common.tests import _test_net_up3

# All tests are coroutines
pytestmark = pytest.mark.asyncio

SRCDIR = os.path.dirname(os.path.abspath(__file__))

#
#                             192.168.0.0/24
#   --+-----------------+------ mgmt0 ----+-----------------+-----------------------
#     | .1              | .2              | .3              | .4              | .5
#   +----+            +----+            +----+            +----+            +----+
#   | h1 | -- net0 -- | r1 | -- net1 -- | rm | -- net2 -- | r2 | -- net2 -- | h1 |
#   +----+ .1      .2 +----+ .2      .3 +----+ .3      .4 +----+ .4      .5 +----+
#          10.0.0.0/24       10.0.1.0/24       10.0.2.0/24       10.0.3.0/24
#           MTU: 9000         MTU: 1500         MTU: 1400        MTU: 9000


@pytest.fixture(scope="module", autouse=True)
async def network_up3(unet, pytestconfig):
    ipv6 = pytestconfig.getoption("--enable-ipv6", False)
    await toggle_forward_pmtu(unet, False)
    await _network_up3(unet, ipv4=True, ipv6=ipv6, minimal=True)


async def test_net_up3(unet, astepf):

    await astepf("Test network ready")
    await _test_net_up3(unet, minimal=True)


async def test_routed_mtu(unet, astepf, pytestconfig):
    h1 = unet.hosts["h1"]

    ipv6 = pytestconfig.getoption("--enable-ipv6", False)
    opts = pytestconfig.getoption("--iptfs-opts", "")
    # opts = "pkt-size 1000"

    await setup_routed_tun(
        unet, iptfs_opts=opts, tun_ipv6=ipv6, network3=True, tun_route_mtu=65535
    )

    await astepf("Send big ping")
    # get the PTMU reply
    h1.cmd_nostatus("ping -w1 -Mdo -s 5000 -c1 10.0.3.5", warn=False)
    h1.cmd_raises("ping -Mdo -s 5000 -c1 10.0.3.5")

    await astepf("Test complete")


async def test_policy_with_routes_mtu(unet, astepf, pytestconfig):
    h1 = unet.hosts["h1"]

    ipv6 = pytestconfig.getoption("--enable-ipv6", False)
    opts = pytestconfig.getoption("--iptfs-opts", "")
    # opts = "pkt-size 1000"

    await setup_policy_tun(
        unet,
        mode="iptfs",
        iptfs_opts=opts,
        tun_ipv6=ipv6,
        network3=True,
        tun_route_mtu=65535,
    )

    await astepf("Send big ping")
    # get the PTMU reply
    h1.cmd_nostatus("ping -w1 -Mdo -s 5000 -c1 10.0.3.5", warn=False)
    h1.cmd_raises("ping -Mdo -s 5000 -c1 10.0.3.5")


async def test_policy_with_table_routes_mtu(unet, astepf, pytestconfig):
    h1 = unet.hosts["h1"]

    ipv6 = pytestconfig.getoption("--enable-ipv6", False)
    opts = pytestconfig.getoption("--iptfs-opts", "")
    # opts = "pkt-size 1000"

    await setup_policy_tun(
        unet,
        mode="iptfs",
        iptfs_opts=opts,
        tun_ipv6=ipv6,
        network3=True,
        tun_route_mtu=65535,
    )

    r1con = unet.hosts["r1"].conrepl
    r2con = unet.hosts["r2"].conrepl

    # Get rid of the standard inner routing routes
    r1con.cmd_nostatus("ip route del 10.0.3.0/24 via 10.0.1.3")
    r2con.cmd_nostatus("ip route del 10.0.0.0/24 via 10.0.2.3")

    r1con.cmd_raises(
        "ip route add 10.0.3.0/24 via 10.0.1.3 src 10.0.0.2 proto static mtu 65536 table 220"
    )
    r2con.cmd_raises(
        "ip route add 10.0.0.0/24 via 10.0.2.3 src 10.0.3.4 proto static mtu 65536 table 220"
    )
    r1con.cmd_raises("ip rule add from all table 220 pref 220")
    r2con.cmd_raises("ip rule add from all table 220 pref 220")

    await astepf("Send big ping")
    # get the PTMU reply
    h1.cmd_nostatus("ping -w1 -Mdo -s 5000 -c1 10.0.3.5", warn=False)
    h1.cmd_raises("ping -Mdo -s 5000 -c1 10.0.3.5")

    await astepf("Test complete")


async def test_policy_with_default_route_mtu(unet, astepf, pytestconfig):
    h1 = unet.hosts["h1"]

    ipv6 = pytestconfig.getoption("--enable-ipv6", False)
    opts = pytestconfig.getoption("--iptfs-opts", "")
    # opts = "pkt-size 1000"

    await setup_policy_tun(
        unet,
        mode="iptfs",
        iptfs_opts=opts,
        tun_ipv6=ipv6,
        network3=True,
        tun_route_mtu=65535,
    )

    r1con = unet.hosts["r1"].conrepl
    r2con = unet.hosts["r2"].conrepl

    # Get rid of the standard inner routing routes
    r1con.cmd_nostatus("ip route del 10.0.3.0/24 via 10.0.1.3")
    r2con.cmd_nostatus("ip route del 10.0.0.0/24 via 10.0.2.3")

    try:
        # Use default route
        r1con.cmd_raises("ip route add default via 192.168.0.254 mtu 65536")
        r2con.cmd_raises("ip route add default via 192.168.0.254 mtu 65536")

        await astepf("Send big ping")
        # get the PTMU reply
        h1.cmd_nostatus("ping -w1 -Mdo -s 5000 -c1 10.0.3.5", warn=False)
        h1.cmd_raises("ping -Mdo -s 5000 -c1 10.0.3.5")

        await astepf("Test complete")
    finally:
        r1con.cmd_nostatus("ip route del default via 192.168.0.254")
        r2con.cmd_nostatus("ip route del default via 192.168.0.254")


async def test_policy_with_dummy_mtu(unet, astepf, pytestconfig):
    h1 = unet.hosts["h1"]

    ipv6 = pytestconfig.getoption("--enable-ipv6", False)
    opts = pytestconfig.getoption("--iptfs-opts", "")
    # opts = "pkt-size 1000"

    await setup_policy_tun(
        unet,
        mode="iptfs",
        iptfs_opts=opts,
        tun_ipv6=ipv6,
        network3=True,
        tun_route_mtu=65535,
    )

    r1con = unet.hosts["r1"].conrepl
    r2con = unet.hosts["r2"].conrepl

    # Get rid of the standard inner routing routes
    r1con.cmd_nostatus("ip route del 10.0.3.0/24 via 10.0.1.3")
    r2con.cmd_nostatus("ip route del 10.0.0.0/24 via 10.0.2.3")

    # Use a dummy interface to nowhere for the inner traffic routes
    try:
        r1con.cmd_raises("ip link add dummy1 type dummy")
        r1con.cmd_raises("ip addr add 192.168.200.1 dev dummy1")
        r1con.cmd_raises("ip link set dummy1 mtu 9000 up")
        r1con.cmd_raises("ip route add default via 192.168.200.1 mtu 65536")

        r2con.cmd_raises("ip link add dummy1 type dummy")
        r2con.cmd_raises("ip addr add 192.168.200.1 dev dummy1")
        r2con.cmd_raises("ip link set dummy1 mtu 9000 up")
        r2con.cmd_raises("ip route add default via 192.168.200.1 mtu 65536")

        await astepf("Send big ping")
        # get the PTMU reply
        h1.cmd_nostatus("ping -w1 -Mdo -s 5000 -c1 10.0.3.5", warn=False)
        h1.cmd_raises("ping -Mdo -s 5000 -c1 10.0.3.5")

        await astepf("Test complete")
    finally:
        # get rid of the dummy stuff as it's not cleaned up by common config code
        r1con.cmd_nostatus("ip route del default via 192.168.200.1")
        r1con.cmd_nostatus("ip addr del 192.168.200.1 dev dummy1")
        r1con.cmd_nostatus("ip link delete dummy1")
        r1con.cmd_nostatus("ip link set dummy1 down")

        r2con.cmd_nostatus("ip route del default via 192.168.200.1")
        r2con.cmd_nostatus("ip addr del 192.168.200.1 dev dummy1")
        r2con.cmd_nostatus("ip link set dummy1 down")
        r2con.cmd_nostatus("ip link delete dummy1")
