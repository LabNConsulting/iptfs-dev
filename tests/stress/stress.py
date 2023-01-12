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
# pylint: disable=wrong-import-position
"Shared functionality between virtual and physical stress tests."

import asyncio
import glob
import logging
import os
import sys
import time

import pytest

# So gross.. but trex plays stupid games with embedded pkgs and path
SRCDIR = os.path.dirname(os.path.abspath(__file__))
trexlib = os.path.join(os.path.dirname(SRCDIR), "external_libs")
scapydir = glob.glob(trexlib + "/scapy*")[0]
sys.path[0:0] = [scapydir]

from common import trexlib, trexutil
from common.config import (  # pylint: disable=unused-import
    setup_policy_tun,
    setup_routed_tun,
    toggle_ipv6,
)
from munet.cli import remote_cli
from trex_stl_lib.api import STLClient

# from munet.testing.util import async_pause_test
# from munet.cli import async_cli

# All tests are coroutines
pytestmark = pytest.mark.asyncio

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


async def start_profile(unet, hostname, tval):
    perfargs = [
        "perf",
        "record",
        "-F",
        "997",
        "-a",
        "-g",
        "-o",
        "/tmp/perf.data",
        "--",
        "sleep",
        tval,
    ]
    host = unet.hosts[hostname]
    await host.async_cmd_raises("sysctl -w kernel.perf_cpu_time_max_percent=75")
    logging.info("Starting perf-profile on %s for %s", hostname, tval)

    p = await host.async_popen(perfargs, use_pty=True)
    p.host = host
    return p


async def stop_profile(p):
    try:
        try:
            # logging.info("signaling perf to exit")
            # p.send_signal(signal.SIGTERM)
            logging.info("waiting for perf to exit")
            o, e = await asyncio.wait_for(p.communicate(), timeout=5.0)
            logging.info(
                "perf rc: %s output: %s error: %s",
                p.returncode,
                o.decode("utf-8"),
                e.decode("utf-8"),
            )
            pdpath = os.path.join(p.host.rundir, "perf.data")
            p.host.cmd_raises(["/bin/cat", "/tmp/perf.data"], stdout=open(pdpath, "wb"))
            p = None
        except TimeoutError:
            logging.warning("perf didn't finish after signal rc: %s", p.returncode)
            raise
        except Exception as error:
            logging.warning(
                "unexpected error while waiting for perf: %s", error, exc_info=True
            )
    finally:
        if p is not None:
            logging.info("terminating perf")
            p.terminate()
            try:
                _, e = await asyncio.wait_for(p.communicate(), timeout=2.0)
                logging.warning("perf rc: %s error: %s", p.returncode, e)
            except TimeoutError:
                logging.warning(
                    "perf didn't finish after terminate rc: %s", p.returncode
                )


#
# Add some options for this test.
#
# def _pytest_addoption(parser):


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


async def _test_policy_small_pkt(unet, pytestconfig, default_rate="100M"):
    iptfs_opts = pytestconfig.getoption("--iptfs-opts")
    profile = bool(pytestconfig.getoption("--profile"))

    args = trexutil.Args(pytestconfig, default_rate=default_rate, default_user_pkt_size=40)

    # await setup_policy_tun(
    if args.mode != "routed":
        await setup_routed_tun(
            unet, ipsec_intf="eth1", mode=args.mode, iptfs_opts=iptfs_opts, trex=True
        )

    # await async_pause_test("after policy setup")

    # Some TREX test
    trex_ip = unet.hosts["trex"].intf_addrs["mgmt0"].ip
    c = STLClient(server=trex_ip, sync_timeout=10, async_timeout=10)
    c.connect()

    def get_streams(
        direction, imix_table, modeclass=None, statsclass=None, ipv6=False, nstreams=1
    ):
        del ipv6
        # return trexlib.get_dynamic_imix_stream(direction, imix_table)
        # return trexlib.get_static_streams_seqnum(
        #     direction, imix_table, modeclass, statsclass, nstreams=nstreams
        # )
        return trexlib.get_static_streams_simple(
            direction, imix_table, modeclass, statsclass, nstreams=nstreams
        )

    async def starting():
        return await start_profile(unet, "r1", args.duration)

    async def beforewait(_):
        pass
        # unet.hosts["r1"].run_in_window("bash")
        # unet.hosts["r2"].run_in_window("bash")

    dutlist = []
    imix_table, pps, avg_ipsize, imix_desc = trexutil.get_imix_table(args, c)
    logging.info("pps: %s av_ipsize: %s desc: %s", pps, avg_ipsize, imix_desc)

    trex_stats, vstats, _ = await trexutil.run_trex_cont_test(
        args,
        c,
        dutlist,
        1,
        get_streams,
        imix_table=imix_table,
        # extended_stats=True)
        startingf=starting if profile else None,
        beforewaitf=beforewait,
        stoppingf=stop_profile if profile else None,
    )
    c.disconnect()
    trexutil.finish_test(__name__, args, dutlist, True, trex_stats, vstats)

    await remote_cli(unet, "cli>", "CLI", True)
    # await async_cli(unet)


async def _test_policy_imix(unet, pytestconfig, default_rate="1G"):
    iptfs_opts = pytestconfig.getoption("--iptfs-opts")
    profile = bool(pytestconfig.getoption("--profile"))

    args = trexutil.Args(pytestconfig, default_rate=default_rate)

    if args.mode != "routed":
        await setup_policy_tun(
            unet, ipsec_intf="eth1", mode=args.mode, iptfs_opts=iptfs_opts, trex=True
        )

    # Some TREX test
    trex_ip = unet.hosts["trex"].intf_addrs["mgmt0"].ip
    c = STLClient(server=trex_ip, sync_timeout=10, async_timeout=10)
    c.connect()

    def get_streams(
        direction, imix_table, modeclass=None, statsclass=None, ipv6=False, nstreams=1
    ):
        del ipv6
        # return trexlib.get_dynamic_imix_stream(direction, imix_table)
        # return trexlib.get_static_streams_seqnum(
        #     direction, imix_table, modeclass, statsclass, nstreams=nstreams
        # )
        return trexlib.get_static_streams_simple(
            direction, imix_table, modeclass, statsclass, nstreams=nstreams
        )

    def starting():
        return start_profile(unet, "r1", args.duration)

    dutlist = []
    imix_table, pps, avg_ipsize, imix_desc = trexutil.get_imix_table(
        args, c, max_imix_size=1400
    )
    logging.info("pps: %s av_ipsize: %s desc: %s", pps, avg_ipsize, imix_desc)
    trex_stats, vstats, _ = await trexutil.run_trex_cont_test(
        args,
        c,
        dutlist,
        1,
        get_streams,
        imix_table=imix_table,
        # extended_stats=True)
        startingf=starting if profile else None,
        stoppingf=stop_profile if profile else None,
    )
    c.disconnect()
    trexutil.finish_test(__name__, args, dutlist, True, trex_stats, vstats)
    # await async_cli(unet)


# async def test_routed_tun_up(unet, r1.conrepl, r2.conrepl, astepf):
#     await setup_routed_tun(unet, r1.conrepl, r2.conrepl)
#     # Some TREX test
