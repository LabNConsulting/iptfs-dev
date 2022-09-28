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
import json
import logging
import os

import pytest
from common.config import _network_up, setup_policy_tun
from common.tests import _test_net_up
from munet.base import cmd_error

# All tests are coroutines
pytestmark = pytest.mark.asyncio

SRCDIR = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module", autouse=True)
async def network_up(unet):
    await _network_up(unet)


#                             192.168.0.0/24
#   --+-------------------+------ mgmt0 ------+-------------------+---
#     | .1                | .2                | .3                | .4
#   +----+              +----+              +----+              +----+
#   | h1 | --- net0 --- | r1 | --- net1 --- | r2 | --- net2 --- | r1 |
#   +----+ .1        .2 +----+ .2        .3 +----+ .3        .4 +----+
#          10.0.0.0/24         10.0.1.0/24         10.0.2.0/24


async def test_net_up(unet):
    await _test_net_up(unet)


async def test_policy_tun_up(unet, astepf):
    h1 = unet.hosts["h1"]
    h2 = unet.hosts["h2"]

    await setup_policy_tun(unet, mode="iptfs")

    # Let's open an iperf3 process on h2.
    logging.info("Starting iperf server on h2")
    args = ["iperf3", "-s"]
    iperfs = await h2.async_popen(args)
    try:
        # And then runt he client
        await astepf("Prior to starting client")
        brate = "10M"
        tval = 4
        logging.info("Starting iperf3 client on h1 at %s for %s", brate, tval)
        args = [
            "iperf3",
            # "--json",
            # "-u",
            # "--length",
            # "1400",
            "-b",
            brate,
            "-t",
            str(tval),
            "-c",
            f"{h2.intf_addrs['eth1'].ip}",
        ]
        iperfc = await h1.async_popen(args)
        try:
            rc = await iperfc.wait()
            logging.info("iperf client on h1 completed rc %s", rc)
            o, e = await iperfc.communicate()
            o = o.decode("utf-8")
            e = e.decode("utf-8")
            assert not rc, f"client failed: {cmd_error(rc, o, e)}"

            logging.info("Results: %s", o)
            # result = json.loads(o)
            # logging.info("Results: %s", json.dumps(result, sort_keys=True, indent=2))
        finally:
            if iperfc.returncode is None:
                iperfc.terminate()
    finally:
        if iperfs.returncode is None:
            iperfs.terminate()
