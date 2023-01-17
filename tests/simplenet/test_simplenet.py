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


async def no_test_user_step(unet, astepf):
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]

    MODE = "mode iptfs"

    spi_1to2 = 0xAAAAAA
    spi_2to1 = 0xBBBBBB

    ipsec_intf = ("eth2",)
    tun_ipv6 = False
    spi_1to2, spi_2to1, sa_auth, sa_enc = get_sa_values(
        use_gcm=True, use_nullnull=False, enc_null=False, tun_ipv6=tun_ipv6
    )

    r1ipp = r1.get_intf_addr(ipsec_intf, ipv6=tun_ipv6)
    if r2 is not None:
        r1ipp = r2.get_intf_addr(ipsec_intf, ipv6=tun_ipv6)
    else:
        # The other side is the switch interface
        net = None
        for net in r1.net_intfs:
            if r1.net_intfs[net] == ipsec_intf:
                break
        assert net is not None, f"can't find network for {ipsec_intf}"
        if tun_ipv6:
            r2ipp = unet.switches[net].ip6_interface
        else:
            r2ipp = unet.switches[net].ip_interface

    r1ip = r1ipp.ip
    r1ipp = r1ipp.network
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


async def test_policy_tun_up(unet, astepf, pytestconfig):
    h1 = unet.hosts["h1"]

    ipv6 = pytestconfig.getoption("--enable-ipv6", False)
    opts = pytestconfig.getoption("--iptfs-opts", "")
    await setup_policy_tun(unet, iptfs_opts=opts, ipv6=ipv6)

    # Need to count ESP packets somehow to verify these were encrypted
    await astepf("first ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    await astepf("second ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    await astepf("third ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))

    if ipv6:
        await astepf("first IPv6 ping")
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))
        await astepf("second IPv6 ping")
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))
        await astepf("third IPv6 ping")
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))


async def test_routed_tun_up(unet, astepf, pytestconfig):
    h1 = unet.hosts["h1"]

    ipv6 = pytestconfig.getoption("--enable-ipv6", False)
    opts = pytestconfig.getoption("--iptfs-opts", "")
    await setup_routed_tun(unet, iptfs_opts=opts, ipv6=ipv6)

    # Need to count ESP packets somehow to verify these were encrypted
    await astepf("first ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    await astepf("second ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    await astepf("third ping")
    logging.debug(h1.cmd_raises("ping -c3 10.0.2.4"))

    if ipv6:
        await astepf("first IPv6 ping")
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))
        await astepf("second IPv6 ping")
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))
        await astepf("third IPv6 ping")
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))
