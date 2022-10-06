#!/usr/bin/env python3
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
import re
import subprocess
from datetime import datetime, timedelta

import pytest
from common.config import setup_policy_tun, toggle_ipv6
from munet.base import comm_error

# from munet.cli import async_cli

# All tests are coroutines
pytestmark = pytest.mark.asyncio

SRCDIR = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module", autouse=True)
async def network_up(unet):
    h1 = unet.hosts["h1"]
    r1 = unet.hosts["r1"]
    r1repl = r1.conrepl

    await toggle_ipv6(unet, enable=False)

    h1.cmd_raises("ip route add 10.0.2.0/24 via 10.0.0.2")
    h1.cmd_raises("ip route add 10.0.1.0/24 via 10.0.0.2")

    r1repl.cmd_raises("ip route add 10.0.2.0/24 via 10.0.1.3")

    # Get the arp entry for unet, and make it permanent
    r1repl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.3")
    r1repl.cmd_raises(f"ip neigh change 10.0.1.3 dev {r1.net_intfs['net1']}")

    # # Remove IP from our scapy node
    unet.cmd_raises("ip addr del 10.0.1.3/24 dev net1")


#                             192.168.0.0/24
#   --+-------------------+------ mgmt0 -------+------
#     | .1                | .2                 | .254
#   +----+              +----+              +------+
#   | h1 | --- net0 --- | r1 | --- net1 --- | unet |
#   +----+ .1        .2 +----+ .2        .3 +------+
#          10.0.0.0/24         10.0.1.0/24


async def test_net_up(unet):
    r1repl = unet.hosts["r1"].conrepl
    h1 = unet.hosts["h1"]

    # h1 pings r1 (qemu side)
    logging.debug(h1.cmd_raises("ping -w1 -i.2 -c1 10.0.0.2"))
    # h1 pings r1 (other side)
    logging.debug(h1.cmd_raises("ping -w1 -i.2 -c1 10.0.1.2"))

    # r1 (qemu side) pings h1
    logging.debug(r1repl.cmd_raises("ping -w1 -i.2 -c1 10.0.0.1"))


def myreadline(f):
    buf = ""
    while True:
        # logging.info("READING 1 CHAR")
        c = f.read(1)
        if not c:
            return buf if buf else None
        buf += c
        # logging.info("READ CHAR: '%s'", c)
        if c == "\n":
            return buf


def _wait_output(p, regex, timeout=120):
    retry_until = datetime.now() + timedelta(seconds=timeout)
    regex = re.compile(regex)
    while datetime.now() < retry_until:
        line = myreadline(p.stdout)
        if not line:
            assert None, f"EOF waiting for '{regex}'"
        line = line.rstrip()
        if line:
            logging.info("GOT LINE: '%s'", line)
        m = regex.search(line)
        if m:
            return m
    assert None, f"Failed to get output withint {timeout}s"


async def gen_pkt_test(unet, astepf, **kwargs):
    pktbin = os.path.join(SRCDIR, "genpkt.py")

    args = [f"--{x}={y}" for x, y in kwargs.items()]
    await astepf(f"Running genpkt.py script: {' '.join(args)}")
    p = unet.popen(
        [pktbin, "-v", "--iface=net1", *args],
        stderr=subprocess.STDOUT,
    )
    try:
        _ = _wait_output(p, "STARTING")

        m = _wait_output(p, r"DECAP (\d+) inner packets")
        ndecap = int(m.group(1))
        assert ndecap == 80, f"Wrong number ({ndecap}, expected 80) return IP packets"

        _ = _wait_output(p, "FINISH")

    except Exception:
        if p:
            p.terminate()
            if p.wait():
                comm_error(p)
            p = None
        raise
    finally:
        if p:
            p.terminate()
            p.wait()


async def test_packet_fragmentation(unet, astepf):
    await astepf("Prior to policy setup")
    await setup_policy_tun(unet, r1only=True)
    await astepf("Prior to gen_pkt_test")
    await gen_pkt_test(unet, astepf, psize=411, mtu=500, pstep=1, count=2)


async def test_small_pkt_agg(unet, astepf):

    await setup_policy_tun(unet, r1only=True)
    await gen_pkt_test(unet, astepf, count=80)
