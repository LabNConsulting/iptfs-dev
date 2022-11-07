# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# December 13 2022, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2022, LabN Consulting, L.L.C.
#
import os

import pytest
from common.config import _network_up
from common.tests import _test_net_up
from munet.testing.fixtures import _unet_impl
from tcpdump import _test_iperf

# All tests are coroutines
pytestmark = pytest.mark.asyncio

SRCDIR = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module", name="unet")
async def _unet(rundir_module, pytestconfig):
    async for x in _unet_impl(rundir_module, pytestconfig, param="munet_1phy"):
        yield x


@pytest.fixture(scope="module", autouse=True)
async def network_up(unet):
    await _network_up(unet)


#                             192.168.0.0/24
#   --+-------------------+------ mgmt0 ------+-------------------+---
#     | .1                | .2                | .3                | .4
#   +----+              +----+              +----+              +----+
#   | h1 | --- phy  --- | r1 | --- net1 --- | r2 | --- net2 --- | r1 |
#   +----+ .1        .2 +----+ .2        .3 +----+ .3        .4 +----+
#          10.0.0.0/24         10.0.1.0/24         10.0.2.0/24

async def test_net_up(unet):
    await _test_net_up(unet, mgmt0=False)


async def test_iperf(unet, astepf):
    await _test_iperf(unet, astepf, "eth1")
