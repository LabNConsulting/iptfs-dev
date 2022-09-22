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
    r2 = unet.hosts["r2"]
    r1repl = r1.conrepl

    await toggle_ipv6(unet, enable=False)

    h1.cmd_raises("ip route add 10.0.2.0/24 via 10.0.0.2")
    h1.cmd_raises("ip route add 10.0.1.0/24 via 10.0.0.2")

    r1repl.cmd_raises("ip route add 10.0.2.0/24 via 10.0.1.3")

    # Get the arp entry for r2, and make it permanent
    r1repl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.3")
    r1repl.cmd_raises(f"ip neigh change 10.0.1.3 dev {r1.net_intfs['net1']}")

    # # Remove IP from our scapy node
    r2.cmd_raises("ip addr del 10.0.1.3/24 dev eth2")


#                             192.168.0.0/24
#   --+-------------------+------ mgmt0 ------+-------------------+---
#     | .1                | .2                | .3                | .4
#   +----+              +----+              +----+              +----+
#   | h1 | --- net0 --- | r1 | --- net1 --- | r2 | --- net2 --- | r1 |
#   +----+ .1        .2 +----+ .2        .3 +----+ .3        .4 +----+
#          10.0.0.0/24         10.0.1.0/24         10.0.2.0/24


async def test_net_up(unet):
    r1repl = unet.hosts["r1"].conrepl
    h1 = unet.hosts["h1"]
    # r2 = unet.hosts["r2"]

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
    while datetime.now() < retry_until:
        # line = p.stdout.readline()
        line = myreadline(p.stdout)
        if not line:
            assert None, f"Timeout waiting for '{regex}'"
        line = line.rstrip()
        if line:
            logging.info("GOT LINE: '%s'", line)
        m = re.search(regex, line)
        if m:
            return m
    assert None, f"Failed to get output withint {timeout}s"


async def test_small_pkt_agg(unet, astepf):
    r2 = unet.hosts["r2"]

    await setup_policy_tun(unet, r1only=True)

    pktbin = os.path.join(SRCDIR, "genpkt.py")

    await astepf("Running genpkt.py script")
    p = r2.popen(
        [
            pktbin,
            "-v",
            "--local=10.0.1.3",
            "--remote=10.0.1.2",
            "--iface=eth2",
            "--mtu=1500",
            "--ping=10.0.0.1",
            "--count=80",
            "--psize=1",
            # "--pstep=1",
            # "--wrap=1",
        ],
        stderr=subprocess.STDOUT,
    )
    try:
        _ = _wait_output(p, "STARTING")
        waitfor = "FINISH"
        _ = _wait_output(p, waitfor)

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


async def test_scapy_script(unet, astepf):
    r2 = unet.hosts["r2"]

    await setup_policy_tun(unet, r1only=True)

    pktbin = os.path.join(SRCDIR, "genpkt.py")

    await astepf("Running genpkt.py script")
    p = r2.popen(
        [
            pktbin,
            "-v",
            "--local=10.0.1.3",
            "--remote=10.0.1.2",
            "--iface=eth2",
            "--mtu=1500",
            "--ping=10.0.0.1",
            "--count=8",
            "--psize=64",
            # "--pstep=1",
            # "--wrap=1",
        ],
        stderr=subprocess.STDOUT,
    )
    try:
        _ = _wait_output(p, "STARTING")
        waitfor = "FINISH"
        _ = _wait_output(p, waitfor)

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
