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
"Test error conditions are handled correctly."

import logging
import os

import pytest
from common.config import _network_up, setup_policy_tun, setup_routed_tun, toggle_ipv6
from common.tests import _test_net_up

# All tests are coroutines
pytestmark = pytest.mark.asyncio

SRCDIR = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module", autouse=True)
async def network_up(unet):
    await _network_up(unet)

    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]

    r1.conrepl.cmd_raises("ip link set eth1 mtu 9000")
    r1.conrepl.cmd_raises("ip link set eth2 mtu 1500")
    r2.conrepl.cmd_raises("ip link set eth1 mtu 9000")
    r2.conrepl.cmd_raises("ip link set eth2 mtu 1500")


#                             192.168.0.0/24
#   --+-------------------+------ mgmt0 ------+-------------------+---
#     | .1                | .2                | .3                | .4
#   +----+              +----+              +----+              +----+
#   | h1 | --- net0 --- | r1 | --- net1 --- | r2 | --- net2 --- | r1 |
#   +----+ .1        .2 +----+ .2        .3 +----+ .3        .4 +----+
#          10.0.0.0/24         10.0.1.0/24         10.0.2.0/24
#                          IP-TFS pkt-size: 560


async def test_net_up(unet):
    await _test_net_up(unet)


async def test_policy_mtu(unet, astepf):
    h1 = unet.hosts["h1"]

    await setup_policy_tun(unet, iptfs_opts="pkt-size 560")

    # Send a successful normal ping
    h1.cmd_raises("ping -c1 10.0.2.4")

    await astepf("Send too big ping over fragmenting policy tunnel")
    rc, _, _ = h1.cmd_status("ping -s 1000 -Mdo -c1 -w1 10.0.2.4")
    assert not rc, "Ping didn't work over fragmenting tunnel"


async def test_routed_mtu(unet, astepf):
    h1 = unet.hosts["h1"]

    await setup_routed_tun(unet, iptfs_opts="pkt-size 560")

    # Send a successful normal ping
    h1.cmd_raises("ping -c1 10.0.2.4")

    await astepf("Send too big ping over fragmenting routed tunnel")
    rc, _, _ = h1.cmd_status("ping -s 1000 -Mdo -c1 -w1 10.0.2.4")
    assert not rc, "Ping didn't work over fragmenting tunnel"


async def test_policy_df_mtu(unet, astepf):
    h1 = unet.hosts["h1"]

    await setup_policy_tun(unet, iptfs_opts="dont-frag pkt-size 560")

    # Send a successful normal ping
    h1.cmd_raises("ping -c1 10.0.2.4")

    await astepf("Send too big ping over non-fragmenting policy tunnel")
    rc, _, _ = h1.cmd_status("ping -s 1000 -Mdo -c1 -w1 10.0.2.4", warn=False)
    assert rc, "Ping worked over dont-frag tunnel"


async def test_routed_df_mtu(unet, astepf):
    h1 = unet.hosts["h1"]

    await setup_routed_tun(unet, iptfs_opts="dont-frag pkt-size 560")

    # Send a successful normal ping
    h1.cmd_raises("ping -c1 10.0.2.4")

    await astepf("Send too big ping over non-fragmenting routed tunnel")
    rc, _, _ = h1.cmd_status("ping -s 1000 -Mdo -c1 -w1 10.0.2.4", warn=False)
    assert rc, "Ping worked over dont-frag tunnel"
