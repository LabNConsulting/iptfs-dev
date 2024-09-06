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

PING_COUNT = 5
INIT_DELAY = 100000


async def test_net_up(unet, astepf):
    await astepf("Before test network up")
    await _test_net_up(unet, ipv6=True)


async def do_ping(host, dest4, dest6, astepf):
    count = PING_COUNT

    await astepf(f"flood {count} IPv4 ping")
    logging.debug(host.cmd_raises(f"ping -q -n -s 8 -f  -c{count} {dest4}"))

    await astepf(f"flood {count} IPv6 ping")
    logging.debug(host.cmd_raises(f"ping -q -n -s 8 -f  -c{count} {dest6}"))


def check_rx_tx_count(host, v6, nrx, ntx):
    # Now validate that we have sent and received the exact number of ESP packets
    base = "fc00:0:0:1::" if v6 else "10.0.1."
    o = host.cmd_raises(f"ip x s l src {base}2")
    assert f" oseq 0x{ntx:x}," in o or f" oseq 0x{ntx:x}\n" in o
    o = host.cmd_raises(f"ip x s l src {base}3")
    assert f" seq 0x{nrx:x}," in o or f" seq 0x{nrx:x}\n" in o


@pytest.mark.parametrize("tun_ipv6", [False, True])
async def test_policy_tun_agg(unet, astepf, tun_ipv6):
    await setup_policy_tun(
        unet,
        mode="iptfs",
        esp_args="replay-window 128",
        iptfs_opts=f"init-delay {INIT_DELAY}",
        ipv6=True,
        tun_ipv6=tun_ipv6,
    )

    await do_ping(unet.hosts["r1"], "10.0.1.3", "fc00:0:0:1::3", astepf)
    check_rx_tx_count(unet.hosts["r1"], tun_ipv6, 2, 2)

    await do_ping(unet.hosts["h1"], "10.0.2.4", "fc00:0:0:2::4", astepf)
    check_rx_tx_count(unet.hosts["r1"], tun_ipv6, 4, 4)


@pytest.mark.parametrize("tun_ipv6", [False, True])
async def test_routed_tun_agg(unet, astepf, tun_ipv6):
    await setup_routed_tun(
        unet,
        mode="iptfs",
        esp_args="replay-window 128",
        esp_flags="esn",
        iptfs_opts=f"init-delay {INIT_DELAY}",
        ipv6=True,
        tun_ipv6=tun_ipv6,
    )

    # We don't have routes setup for local originated pings
    await do_ping(unet.hosts["h1"], "10.0.2.4", "fc00:0:0:2::4", astepf)
    check_rx_tx_count(unet.hosts["r1"], tun_ipv6, 2, 2)
