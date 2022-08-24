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
from common.config import setup_policy_tun, setup_routed_tun

# All tests are coroutines
pytestmark = pytest.mark.asyncio

SRCDIR = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module", autouse=True)
async def network_up(unet):
    h1 = unet.hosts["h1"]
    h2 = unet.hosts["h2"]
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]
    for _, repl in [(r1, r1.conrepl), (r2, r2.conrepl)]:
        repl.cmd_raises("sysctl -w net.ipv6.conf.all.autoconf=0")
        repl.cmd_raises("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        repl.cmd_raises("sysctl -w net.ipv4.ip_forward=1")
        repl.cmd_raises("ip link set lo up")

    h1.cmd_raises("ip route add 10.0.2.0/24 via 10.0.0.2")
    h1.cmd_raises("ip route add 10.0.1.0/24 via 10.0.0.2")

    r1.conrepl.cmd_raises("ip route add 10.0.2.0/24 via 10.0.1.3")
    r2.conrepl.cmd_raises("ip route add 10.0.0.0/24 via 10.0.1.2")

    h2.cmd_raises("ip route add 10.0.1.0/24 via 10.0.2.3")
    h2.cmd_raises("ip route add 10.0.0.0/24 via 10.0.2.3")


#                             192.168.0.0/24
#   --+-------------------+------ mgmt0 ------+-------------------+---
#     | .1                | .2                | .3                | .4
#   +----+              +----+              +----+              +----+
#   | h1 | --- net0 --- | r1 | --- net1 --- | r2 | --- net2 --- | r1 |
#   +----+ .1        .2 +----+ .2        .3 +----+ .3        .4 +----+
#          10.0.0.0/24         10.0.1.0/24         10.0.2.0/24


async def test_net_up(unet):
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]
    # pings mgmt0 bridge
    logging.debug(unet.hosts["h1"].cmd_raises("ping -w1 -i.2 -c1 192.168.0.254"))
    # h1 pings r1 (qemu side)
    logging.debug(unet.hosts["h1"].cmd_raises("ping -w1 -i.2 -c1 10.0.0.2"))
    # h1 pings r1 (other side)
    logging.debug(unet.hosts["h1"].cmd_raises("ping -w1 -i.2 -c1 10.0.1.2"))
    # h1 pings r2
    logging.debug(unet.hosts["h1"].cmd_raises("ping -w1 -i.2 -c1 10.0.1.3"))
    # h1 pings h2
    logging.debug(unet.hosts["h1"].cmd_raises("ping -w1 -i.2 -c1 10.0.2.4"))
    # r1 (qemu side) pings mgmt0 brige
    logging.debug(r1.conrepl.cmd_raises("ping -w1 -i.2 -c1 192.168.0.254"))
    # r1 (qemu side) pings h1
    logging.debug(r1.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.0.1"))
    # logging.debug(r1.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.2"))
    # r1 (qemu side) pings r2 (qemu side)
    logging.debug(r1.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.3"))

    # r2 (qemu side) pings all mgmt0
    logging.debug(r2.conrepl.cmd_raises("ping -w1 -i.2 -c1 192.168.0.254"))
    logging.debug(r2.conrepl.cmd_raises("ping -w1 -i.2 -c1 192.168.0.1"))
    logging.debug(r2.conrepl.cmd_raises("ping -w1 -i.2 -c1 192.168.0.2"))
    logging.debug(r2.conrepl.cmd_raises("ping -w1 -i.2 -c1 192.168.0.3"))
    logging.debug(r2.conrepl.cmd_raises("ping -w1 -i.2 -c1 192.168.0.4"))

    # r2 (qemu side) pings r1 (qemu side)
    logging.debug(r2.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.2"))
    # logging.debug(r2.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.2.3"))
    # r2 (qemu side) pings h2
    logging.debug(r2.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.2.4"))

    # h2 pings mgmt0 bridge
    logging.debug(unet.hosts["h2"].cmd_raises("ping -w1 -i.2 -c1 192.168.0.254"))
    # h2 pings r2 (qemu side)
    logging.debug(unet.hosts["h2"].cmd_raises("ping -w1 -i.2 -c1 10.0.2.3"))
    # h2 pings r2 (other side)
    logging.debug(unet.hosts["h2"].cmd_raises("ping -w1 -i.2 -c1 10.0.1.3"))
    # h2 pings r1
    logging.debug(unet.hosts["h2"].cmd_raises("ping -w1 -i.2 -c1 10.0.1.2"))
    # h2 pings h1
    logging.debug(unet.hosts["h2"].cmd_raises("ping -w1 -i.2 -c1 10.0.0.1"))


async def no_test_user_step(unet, astepf):
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]

    MODE = "mode iptfs"

    spi_1to2 = 0xAAAAAA
    spi_2to1 = 0xBBBBBB

    sa_auth = "auth sha256 0x0123456789ABCDEF0123456789ABCDEF"
    sa_enc = "enc aes 0xFEDCBA9876543210FEDCBA9876543210"
    # sa_auth = "auth sha256 0x0123456789ABCDEF0123456789ABCDEF"
    # sa_enc = 'enc cipher_null ""'

    r1ipp = r1.intf_addrs["eth2"]
    r1ip = r1ipp.ip
    r1ipp = r1ipp.network
    r2ipp = r2.intf_addrs["eth2"]
    r2ip = r2ipp.ip
    r2ipp = r2ipp.network

    #
    # SAs
    #

    await astepf("configuring SA outbound")

    repl = r1.conrepl
    repl.cmd_raises(
        f"ip xfrm state add src {r1ip} dst {r2ip} proto esp "
        f"spi {spi_1to2} {MODE} {sa_auth} {sa_enc} "
        f"reqid 0x200"
    )

    await astepf("configuring SA inbound")

    repl.cmd_raises(
        f"ip xfrm state add src {r2ip} dst {r1ip} proto esp "
        f"spi {spi_2to1} {MODE} {sa_auth} {sa_enc} "
        f"reqid 0x300"
    )

    await astepf("configuring outbound policy")

    x1ipp, x2ipp = ("10.0.0.0/24", "10.0.2.0/24")
    direction = "dir out"
    repl.cmd_raises(
        f"ip xfrm policy add src {x1ipp} dst {x2ipp} {direction} "
        f"tmpl src {r1ip} dst {r2ip} proto esp {MODE} "
        f"reqid 0x200",
        # " spi {spi_1to2} "
    )

    await astepf("configuring forwarding policy")

    direction = "dir fwd"
    repl.cmd_raises(
        f"ip xfrm policy add src {x2ipp} dst {x1ipp} {direction} "
        f"tmpl src {r2ip} dst {r1ip} proto esp {MODE} "
        f"reqid 0x300",
    )

    await astepf("configuring inbound policy")

    direction = "dir in"
    repl.cmd_raises(
        f"ip xfrm policy add src {x2ipp} dst {x1ipp} {direction} "
        f"tmpl src {r2ip} dst {r1ip} proto esp {MODE} "
        f"reqid 0x300",
    )


async def test_policy_tun_up(unet, astepf):
    h1 = unet.hosts["h1"]

    await setup_policy_tun(unet)

    # Need to count ESP packets somehow to verify these were encrypted
    # logging.debug(h1.cmd_raises("ping -w1 -i.2 -c1 10.0.1.3"))
    # logging.debug(h1.cmd_raises("ping -w1 -i.2 -c1 10.0.2.3"))
    await astepf("first ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    await astepf("second ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    await astepf("third ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))

    # logging.debug(r1.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.3"))
    # logging.debug(r1.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.2.3"))
    # logging.debug(r1.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.2.4"))

    # logging.debug(r2.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.2"))
    # logging.debug(r2.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.0.2"))
    # logging.debug(r2.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.0.1"))

    # logging.debug(h2.cmd_raises("ping -w1 -i.2 -c1 10.0.1.2"))
    # logging.debug(h2.cmd_raises("ping -w1 -i.2 -c1 10.0.0.2"))
    # logging.debug(h2.cmd_raises("ping -w1 -i.2 -c1 10.0.0.1"))

    # await async_cli(unet)


async def test_routed_tun_up(unet):
    h1 = unet.hosts["h1"]
    # h2 = unet.hosts["h2"]

    await setup_routed_tun(unet)

    # await astepf("first ping")
    # logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    # await astepf("second ping")
    # logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    # await astepf("third ping")
    logging.debug(h1.cmd_raises("ping -c3 10.0.2.4"))

    # logging.debug(h1.cmd_raises("ping -w3 -i.1 -c3 10.0.2.4"))

    # Encrypt  when directly to black interface port
    # This doesnt work
    # r1.conrepl.cmd_raises("ip route add 10.0.1.3/32 dev ipsec0")
    # r2.conrepl.cmd_raises("ip route add 10.0.1.2/32 dev ipsec0")

    # logging.debug(h1.cmd_raises("ping -w1 -i.2 -c1 10.0.1.3"))
    # logging.debug(h1.cmd_raises("ping -w1 -i.2 -c1 10.0.2.3"))
    # logging.debug(h1.cmd_raises("ping -w1 -i.1 -c1 10.0.2.4"))

    # logging.debug(r1.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.3"))
    # logging.debug(r1.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.2.3"))
    # logging.debug(r1.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.2.4"))

    # logging.debug(r2.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.2"))
    # logging.debug(r2.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.0.2"))
    # logging.debug(r2.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.0.1"))

    # logging.debug(h2.cmd_raises("ping -w1 -i.2 -c1 10.0.1.2"))
    # logging.debug(h2.cmd_raises("ping -w1 -i.2 -c1 10.0.0.2"))
    # logging.debug(h2.cmd_raises("ping -w1 -i.2 -c1 10.0.0.1"))

    # await async_cli(unet)
