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
import subprocess

import pytest
from common.config import _network_up, setup_policy_tun
from common.tests import _test_net_up
from munet.base import cmd_error
from munet.testing.fixtures import _unet_impl

# All tests are coroutines
pytestmark = pytest.mark.asyncio

SRCDIR = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module", autouse=True)
async def checkrun(pytestconfig):
    if not pytestconfig.option.enable_physical:
        pytest.skip(
            "Physical interface test being skipped, pass --enable-physical",
            allow_module_level=True,
        )


@pytest.fixture(scope="module", name="unet")
async def _unet(rundir_module, pytestconfig):
    async for x in _unet_impl(rundir_module, pytestconfig, "munet_phy"):
        yield x


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


async def _test_tcp(unet, astepf):
    h1 = unet.hosts["h1"]
    h2 = unet.hosts["h2"]
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]

    await setup_policy_tun(unet, mode="iptfs")

    # # Keep everything SUPER simple
    # for host in (r1, r2):
    #     host.comrepl.cmd_raises("ethtool -K eth1 tx off sg off tso off rx off gso off")
    #     host.comrepl.cmd_raises("ethtool -K eth2 tx off sg off tso off rx off gso off")
    #     # host.cmd_raises("ethtool -K eth1 tso off gso off")
    #     # host.cmd_raises("ethtool -K eth2 tso off gso off")
    # for host in (h1, h2):
    #     host.cmd_raises("sysctl -w net.ipv4.ip_no_pmtu_disc=1")
    #     host.cmd_raises("sysctl -w net.ipv4.route.min_pmtu=1200")
    #     host.cmd_raises("sysctl -w net.ipv4.tcp_mtu_probing=0")

    # Let's open an tcp process on h2.
    logging.info("Starting TCP server on h2")
    script = os.path.join(unet.config_dirname, "../../common/send-recv.py")
    args = [script, "-s"]
    tcps = await h2.async_popen(args)
    try:
        # And then runt he client
        await astepf("Prior to starting client")
        size = "100M"
        logging.info("Starting tcp client on h1 sending %s bytes", size)
        args = [
            script,
            "-l",
            size,
            f"{h2.intf_addrs['eth1'].ip}",
        ]
        tcpc = await h1.async_popen(args, stderr=subprocess.STDOUT)
        try:
            rc = await tcpc.wait()
            logging.info("tcp client on h1 completed rc %s", rc)
            o, _ = await tcpc.communicate()
            o = o.decode("utf-8")
            assert not rc, f"client failed: {cmd_error(rc, o, '')}"
            if o:
                logging.info('tcp client exits with output: "%s"', o)
            else:
                logging.info("tcp client exits cleanly")
        finally:
            if tcpc.returncode is None:
                tcpc.terminate()
    finally:
        if tcps.returncode is None:
            tcps.terminate()


async def test_iperf(unet, astepf):
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
        tval = 10
        brate = "10M"
        logging.info("Starting iperf3 client on h1 for %s", tval)
        # brate = "10M"
        # logging.info("Starting iperf3 client on h1 at %s for %s", brate, tval)
        args = [
            "iperf3",
            # "--json",
            # "-u",
            # "--length",
            # "1400",
            # "-b",
            # brate,
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
