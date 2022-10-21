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
import logging
import os

import pytest
from common.config import _network_up, setup_policy_tun, setup_routed_tun
from common.tests import _test_net_up


# All tests are coroutines
pytestmark = pytest.mark.asyncio

SRCDIR = os.path.dirname(os.path.abspath(__file__))


#                             192.168.0.0/24
#   --+-------------------+------ mgmt0 ------+-------------------+---
#     | .1                | .2                | .3                | .4
#   +----+              +----+              +----+              +----+
#   | h1 | --- net0 --- | r1 | --- net1 --- | r2 | --- net2 --- | h2 |
#   +----+ .1        .2 +----+ .2        .3 +----+ .3        .4 +----+
#          10.0.0.0/24         10.0.1.0/24         10.0.2.0/24


@pytest.fixture(scope="module", autouse=True)
async def checkrun(pytestconfig):
    if not pytestconfig.option.enable_physical:
        pytest.skip(
            "Physical interface test being skipped, pass --enable-physical",
            allow_module_level=True,
        )


@pytest.fixture(scope="module", autouse=True)
async def network_up(unet):
    await _network_up(unet)


async def test_net_up(unet):
    await _test_net_up(unet, mgmt0=False)


async def test_policy_tun_up(unet, astepf):
    h1 = unet.hosts["h1"]

    await setup_policy_tun(unet, ipsec_intf="eth1")

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

    await setup_routed_tun(unet, ipsec_intf="eth1")

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
