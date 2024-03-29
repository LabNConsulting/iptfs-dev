# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# September 16 2023, Christian Hopps <chopps@labn.net>
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
"Find max rate using physical ethernet interfaces."
import logging
import os

import pytest
from munet.testing.fixtures import _unet_impl
from stress import _network_up, _test_policy_imix, _test_policy_small_pkt

# All tests are coroutines
pytestmark = pytest.mark.asyncio


SRCDIR = os.path.dirname(os.path.abspath(__file__))

#                    192.168.0.0/24
#   --+--------------------+------ mgmt0 -------+
#     | .1                 | .2                 | .3
#   +----+               +----+              +----+
#   |trex| ---- p2p ---- | r1 | --- net1 --- | r2 |
#   |    | .1         .2 +----+ .2        .3 +----+
#   |    |  1l.0.0.0/24         10.0.1.0/24     | .3
#   |    |                                      |
#   |    | ---- p2p ----------------------------+
#   |    | .1          12.0.0.0/24
#   +----+


@pytest.fixture(scope="module", autouse=True)
async def checkrun(pytestconfig):
    if not pytestconfig.option.enable_physical:
        pytest.skip(
            "Physical interface test being skipped, pass --enable-physical",
            allow_module_level=True,
        )


@pytest.fixture(scope="module", name="unet")
async def _unet(rundir_module, pytestconfig):
    async for x in _unet_impl(
        rundir_module,
        pytestconfig,
        param="munet_phy",
        unshare=True,
        top_level_pidns=False,
    ):
        yield x


@pytest.fixture(scope="module", autouse=True)
async def network_up(unet):
    await _network_up(unet)


async def test_net_up(unet):
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]
    # r1 (qemu side) pings r2 (qemu side)
    logging.debug(r1.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.3"))

    # r2 (qemu side) pings r1 (qemu side)
    logging.debug(r2.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.2"))

    # Unfortunately TREX with physical interfaces does not reply to PINGs
    # so we cannot ping test those ports


async def test_policy_small_pkt(unet, pytestconfig):
    try:
        await _test_policy_small_pkt(unet, pytestconfig, default_rate="100M")
    except Exception as ex:
        breakpoint()
        print("Got excpetion: ", ex)
    else:
        print("Clean run")


async def test_policy_imix(unet, pytestconfig):
    try:
        await _test_policy_imix(unet, pytestconfig, default_rate="1G")
    except Exception as ex:
        breakpoint()
        print("Got excpetion: ", ex)
    else:
        print("Clean run")
