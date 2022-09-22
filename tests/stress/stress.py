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
"Shared functionality between virtual and physical stress tests."
import logging
import os
import time

import pytest
from common import testutil, trexlib
from common.config import setup_policy_tun, toggle_ipv6
from trex_stl_lib.api import STLClient

# from munet.testing.util import async_pause_test

# from munet.cli import async_cli

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


async def _network_up(unet):
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]

    await toggle_ipv6(unet, enable=False)

    r1.conrepl.cmd_raises("ip route add 12.0.0.0/24 via 10.0.1.3")
    r2.conrepl.cmd_raises("ip route add 11.0.0.0/24 via 10.0.1.2")

    # trex local routes
    r1.conrepl.cmd_raises("ip route add 16.0.0.0/8 via 11.0.0.1")
    r2.conrepl.cmd_raises("ip route add 48.0.0.0/8 via 12.0.0.1")

    # trex remote routes
    r1.conrepl.cmd_raises("ip route add 48.0.0.0/8 via 10.0.1.3")
    r2.conrepl.cmd_raises("ip route add 16.0.0.0/8 via 10.0.1.2")

    # Pin the ARP entries
    logging.debug(r1.conrepl.cmd_status("ping -w1 -i.2 -c1 10.0.1.3"))
    logging.debug(r1.conrepl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.3"))
    r1.conrepl.cmd_raises("ip neigh change 10.0.1.3 dev eth1")
    r2.conrepl.cmd_raises("ip neigh change 10.0.1.2 dev eth1")

    # TREX doesn't answer pings and this is causing us ARP headaches apparently :(

    for _ in range(0, 30):
        # logging.debug(r1.conrepl.cmd_nostatus("ping -w1 -i1 -c1 11.0.0.1"))
        rc, output = r1.conrepl.cmd_status("ip neigh get 11.0.0.1 dev eth2")
        logging.info("neighbor on r1: rc %s output: %s", rc, output)
        if not rc and "FAILED" not in output:
            break
        time.sleep(1)
    else:
        assert False, "Failed to get ARP for trex port on r1"
    r1.conrepl.cmd_raises("ip neigh change 11.0.0.1 dev eth2")

    for _ in range(0, 10):
        # logging.debug(r2.conrepl.cmd_nostatus("ping -w1 -i1 -c1 12.0.0.1"))
        rc, output = r2.conrepl.cmd_status("ip neigh get 12.0.0.1 dev eth2")
        logging.info("neighbor on r2: rc %s output: %s", rc, output)
        if not rc and "FAILED" not in output:
            break
        if "FAILED" in output:
            rc, output = r2.conrepl.cmd_status("ip neigh del 12.0.0.1 dev eth2")
        time.sleep(1)

    else:
        rc, output = r2.conrepl.cmd_status("ip neigh del 12.0.0.1 dev eth2")
        r2.conrepl.cmd_raises("ip neigh add 12.0.0.1 lladdr 02:cc:cc:cc:02:01 dev eth2")
        # assert False, "Failed to get ARP for trex port on r2"
    r2.conrepl.cmd_raises("ip neigh change 12.0.0.1 dev eth2")


def convert_number(value):
    """Convert a number value with a possible suffix to an integer.

    >>> convert_number("100k") == 100 * 1024
    True
    >>> convert_number("100M") == 100 * 1000 * 1000
    True
    >>> convert_number("100Gi") == 100 * 1024 * 1024 * 1024
    True
    >>> convert_number("55") == 55
    True
    """
    if value is None:
        return None
    rate = str(value)
    base = 1000
    if rate[-1] == "i":
        base = 1024
        rate = rate[:-1]
    suffix = "KMGTPEZY"
    index = suffix.find(rate[-1])
    if index == -1:
        base = 1024
        index = suffix.lower().find(rate[-1])
    if index != -1:
        rate = rate[:-1]
    return int(rate) * base ** (index + 1)


async def _test_policy_small_pkt(unet, rate):
    await setup_policy_tun(unet, trex=True)

    # await async_pause_test("after policy setup")

    args = testutil.Args(rate=rate, user_packet_size=40)

    # Some TREX test
    trex_ip = unet.hosts["trex"].intf_addrs["mgmt0"].ip
    c = STLClient(server=trex_ip, sync_timeout=10, async_timeout=10)
    c.connect()

    def get_streams(direction, imix_table, modeclass=None, statsclass=None, ipv6=False):
        del ipv6
        # return trexlib.get_dynamic_imix_stream(direction, imix_table)
        return trexlib.get_static_streams(
            direction, imix_table, modeclass, statsclass, nstreams=args.connections
        )

    dutlist = []
    imix_table, pps, avg_ipsize, imix_desc = testutil.get_imix_table(args, c)
    logging.info("pps: %s av_ipsize: %s imix_desc: %s", pps, avg_ipsize, imix_desc)
    trex_stats, vstats, _ = await testutil.run_trex_cont_test(
        args,
        c,
        dutlist,
        1,
        get_streams,
        imix_table=imix_table,
        # extended_stats=True)
    )
    c.disconnect()
    testutil.finish_test(__name__, args, dutlist, True, trex_stats, vstats)
    # await async_cli(unet)


async def _test_policy_imix(unet, rate):
    await setup_policy_tun(unet, trex=True)

    args = testutil.Args(rate=rate, old_imix=True)

    # Some TREX test
    trex_ip = unet.hosts["trex"].intf_addrs["mgmt0"].ip
    c = STLClient(server=trex_ip, sync_timeout=10, async_timeout=10)
    c.connect()

    def get_streams(direction, imix_table, modeclass=None, statsclass=None, ipv6=False):
        del ipv6
        # return trexlib.get_dynamic_imix_stream(direction, imix_table)
        return trexlib.get_static_streams(
            direction, imix_table, modeclass, statsclass, nstreams=args.connections
        )

    dutlist = []
    imix_table, pps, avg_ipsize, imix_desc = testutil.get_imix_table(
        args, c, max_imix_size=1436
    )
    logging.info("pps: %s av_ipsize: %s imix_desc: %s", pps, avg_ipsize, imix_desc)
    trex_stats, vstats, _ = await testutil.run_trex_cont_test(
        args,
        c,
        dutlist,
        1,
        get_streams,
        imix_table=imix_table,
        # extended_stats=True)
    )
    c.disconnect()
    testutil.finish_test(__name__, args, dutlist, True, trex_stats, vstats)
    # await async_cli(unet)


# async def test_routed_tun_up(unet, r1.conrepl, r2.conrepl, astepf):
#     await setup_routed_tun(unet, r1.conrepl, r2.conrepl)
#     # Some TREX test
