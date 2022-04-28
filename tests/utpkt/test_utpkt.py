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
import time
from datetime import datetime, timedelta

import pytest
from munet.base import comm_error

# from munet.cli import async_cli

# All tests are coroutines
pytestmark = pytest.mark.asyncio

SRCDIR = os.path.dirname(os.path.abspath(__file__))


async def console(unet, rtr):
    # cmd = ["socat", "-,rawer,echo=0,icanon=0", "unix-connect:/tmp/qemu-sock/console"]
    cmd = ["socat", "-", "unix-connect:/tmp/qemu-sock/console"]
    # cmd = [
    #     "socat",
    #     "/dev/stdin,rawer,echo=0,icanon=0",
    #     "unix-connect:/tmp/qemu-sock/console",
    # ]
    rtr = unet.hosts[rtr] if isinstance(rtr, str) else rtr
    time.sleep(1)
    repl = await rtr.console(cmd, user="root", use_pty=False, trace=True)
    repl.cmd_status("set +o emacs")
    return repl


@pytest.fixture(scope="module", name="r1repl")
async def r1repl_(unet):
    return await console(unet, unet.hosts["r1"])


@pytest.fixture(scope="module", autouse=True)
async def network_up(unet, r1repl):
    h1 = unet.hosts["h1"]
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]

    # Need to configure inside qemu now
    r1repl.cmd_raises("sysctl -w net.ipv6.conf.all.autoconf=0")
    r1repl.cmd_raises("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    r1repl.cmd_raises("sysctl -w net.ipv4.ip_forward=1")
    r1repl.cmd_raises("ip link set lo up")
    for i in range(0, len(r1.intf_addrs)):
        r1repl.cmd_raises(f"ip link set eth{i} up")
        r1repl.cmd_raises(f"ip addr add {r1.intf_addrs[f'eth{i}']} dev eth{i}")

    h1.cmd_raises("ip route add 10.0.2.0/24 via 10.0.0.2")
    h1.cmd_raises("ip route add 10.0.1.0/24 via 10.0.0.2")

    r1repl.cmd_raises("ip route add 10.0.2.0/24 via 10.0.1.3")

    # Get the arp entry for r2, and make it permanent
    r1repl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.3")
    r1repl.cmd_raises(f"ip neigh change 10.0.1.3 dev {r1.net_intfs['net1']}")

    # # Remove IP from our scapy node
    r2.cmd_raises("ip addr del 10.0.1.3/24 dev eth1")


#                             192.168.0.0/24
#   --+-------------------+------ mgmt0 ------+-------------------+---
#     | .1                | .2                | .3                | .4
#   +----+              +----+              +----+              +----+
#   | h1 | --- net0 --- | r1 | --- net1 --- | r2 | --- net2 --- | r1 |
#   +----+ .1        .2 +----+ .2        .3 +----+ .3        .4 +----+
#          10.0.0.0/24         10.0.1.0/24         10.0.2.0/24


async def test_net_up(unet, r1repl):
    h1 = unet.hosts["h1"]
    # r2 = unet.hosts["r2"]

    # h1 pings r1 (qemu side)
    logging.debug(h1.cmd_raises("ping -w1 -i.2 -c1 10.0.0.2"))
    # h1 pings r1 (other side)
    logging.debug(h1.cmd_raises("ping -w1 -i.2 -c1 10.0.1.2"))

    # r1 (qemu side) pings h1
    logging.debug(r1repl.cmd_raises("ping -w1 -i.2 -c1 10.0.0.1"))


MODE = "mode iptfs"
USE_GCM = True
USE_NULLNULL = False


async def setup_policy_tun(unet, r1repl):
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]

    reqid_1to2 = 0x10
    reqid_2to1 = 0x11

    if not USE_GCM:
        if USE_NULLNULL:
            spi_1to2 = 0xAAAAAA
            spi_2to1 = 0xBBBBBB
            sa_auth = 'auth digest_null ""'
            sa_enc = 'enc cipher_null ""'
        else:
            spi_1to2 = 0xAAAA
            spi_2to1 = 0xBBBB
            sa_auth = "auth sha1 0x4339314b55523947594d6d3547666b45764e6a58"
            sa_enc = 'enc cipher_null ""'
    else:
        spi_1to2 = 0xAA
        spi_2to1 = 0xBB
        sa_auth = ""
        sa_enc = (
            'aead "rfc4106(gcm(aes))" '
            "0x4a506a794f574265564551694d6537681A2B1A2B "
            "128"
            # "0x4a506a794f574265564551694d6537684a506a794f574265564551694d6537681A2B1A2B "
            # "256"
        )

    r1ipp = r1.net_addr("net1")
    r2ipp = r2.net_addr("net1")
    r1ip = r1ipp.ip
    r1ipp = r1ipp.network
    r2ip = r2ipp.ip
    r2ipp = r2ipp.network

    r1repl.cmd_status("ip x s deleteall")
    r1repl.cmd_status("ip x p deleteall")

    for r, repl in [(r1, r1repl)]:  # , (r2, r2repl)]:
        #
        # SAs
        #
        repl.cmd_raises(
            f"ip xfrm state add src {r1ip} dst {r2ip} proto esp "
            f"spi {spi_1to2} {MODE} {sa_auth} {sa_enc} "
            f"reqid {reqid_1to2}"
        )
        repl.cmd_raises(
            f"ip xfrm state add src {r2ip} dst {r1ip} proto esp "
            f"spi {spi_2to1} {MODE} {sa_auth} {sa_enc} "
            f"reqid {reqid_2to1}"
        )

        #
        # Policy
        #
        for x1ipp, x2ipp in [
            ("10.0.0.0/24", "10.0.1.0/24"),  # host to router
            ("10.0.1.0/24", "10.0.1.0/24"),  # router to router
            ("10.0.1.0/24", "10.0.2.0/24"),  # host to router
            ("10.0.0.0/24", "10.0.2.0/24"),  # host to host
        ]:
            for direction in ["dir out"] if r == r1 else ["dir fwd", "dir in"]:
                repl.cmd_raises(
                    f"ip xfrm policy add src {x1ipp} dst {x2ipp} {direction} "
                    f"tmpl src {r1ip} dst {r2ip} proto esp {MODE} "
                    f"reqid {reqid_1to2}",
                )
            for direction in ["dir out"] if r == r2 else ["dir fwd", "dir in"]:
                repl.cmd_raises(
                    f"ip xfrm policy add src {x2ipp} dst {x1ipp} {direction} "
                    f"tmpl src {r2ip} dst {r1ip} proto esp {MODE} "
                    f"reqid {reqid_2to1}",
                )


async def setup_routed_tun(unet, r1repl):
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]

    reqid_1to2 = 8
    reqid_2to1 = 9

    if not USE_GCM:
        if USE_NULLNULL:
            spi_1to2 = 0xAAAA
            spi_2to1 = 0xBBBB
            sa_auth = 'auth digest_null ""'
            # sa_auth = "auth sha256 0x0123456789ABCDEF0123456789ABCDEF"
            # sa_auth = 'auth digest_null ""'
            sa_enc = 'enc cipher_null ""'
        else:
            spi_1to2 = 0xAAAA
            spi_2to1 = 0xBBBB
            sa_auth = "auth sha1 0x4339314b55523947594d6d3547666b45764e6a58"
            # sa_auth = "auth sha256 0x0123456789ABCDEF0123456789ABCDEF"
            # sa_auth = 'auth digest_null ""'
            sa_enc = 'enc cipher_null ""'
    else:
        spi_1to2 = 0xAA
        spi_2to1 = 0xBB
        sa_auth = ""
        sa_enc = (
            'aead "rfc4106(gcm(aes))" '
            "0x4a506a794f574265564551694d6537681A2B1A2B "
            "128"
            # "0x4a506a794f574265564551694d6537684a506a794f574265564551694d6537681A2B1A2B "
            # "256"
        )

    r1ipp = r1.net_addr("net1")
    r2ipp = r2.net_addr("net1")
    r1ip = r1ipp.ip
    r1ipp = r1ipp.network
    r2ip = r2ipp.ip
    r2ipp = r2ipp.network

    # Get rid of non-ipsec routes
    r1repl.cmd_raises("ip route del 10.0.2.0/24 via 10.0.1.3")
    # r2repl.cmd_raises("ip route del 10.0.0.0/24 via 10.0.1.2")

    r1repl.cmd_status("ip x s deleteall")
    r1repl.cmd_status("ip x p deleteall")

    for r, repl in [(r1, r1repl)]:  # , (r2, r2repl)]:
        #
        # SAs
        #
        if r == r1:
            oreqid, ireqid = reqid_1to2, reqid_2to1
            ospi, ispi = spi_1to2, spi_2to1
            lip = r1ip
            rip = r2ip
        else:
            oreqid, ireqid = reqid_2to1, reqid_1to2
            ospi, ispi = spi_2to1, spi_1to2
            lip = r2ip
            rip = r1ip

        repl.cmd_raises(
            f"ip xfrm state add src {r1ip} dst {r2ip} proto esp "
            f"spi {spi_1to2} {MODE} {sa_auth} {sa_enc} "
            f"if_id 55 reqid {reqid_1to2}"
        )
        repl.cmd_raises(
            f"ip xfrm state add src {r2ip} dst {r1ip} proto esp "
            f"spi {spi_2to1} {MODE} {sa_auth} {sa_enc} "
            f"if_id 55 reqid {reqid_2to1}"
        )

        repl.cmd_raises(
            f"ip link add ipsec0 type xfrm dev {r.net_intfs['net1']} if_id 55"
        )
        repl.cmd_raises("sysctl -w net.ipv4.conf.ipsec0.disable_policy=1")
        repl.cmd_raises("ip link set ipsec0 up")

        #
        # Policy
        #
        xdef = "0.0.0.0/0"

        # Interface based policy for everything else
        direction = "dir out"
        repl.cmd_raises(
            f"ip xfrm policy add if_id 55 src {xdef} dst {xdef} {direction}"
            f" tmpl src {lip} dst {rip} proto esp {MODE} reqid {oreqid}"
        )

        for direction in ["dir fwd", "dir in"]:
            repl.cmd_raises(
                f"ip xfrm policy add if_id 55 src {xdef} dst {xdef} {direction} "
                f"tmpl src {rip} dst {lip} proto esp {MODE} reqid {ireqid}"
            )

    # Add ipsec0 based routes
    r1repl.cmd_raises("ip route add 10.0.2.0/24 dev ipsec0 src 10.0.1.2")
    # r2repl.cmd_raises("ip route add 10.0.0.0/24 dev ipsec0 src 10.0.1.3")


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


async def test_small_pkt_agg(unet, r1repl, astepf):
    r2 = unet.hosts["r2"]

    await setup_policy_tun(unet, r1repl)
    # await setup_routed_tun(unet, r1repl)

    pktbin = os.path.join(SRCDIR, "genpkt.py")

    await astepf("Running genpkt.py script")
    p = r2.popen(
        [
            pktbin,
            "-v",
            "--local=10.0.1.3",
            "--remote=10.0.1.2",
            "--iface=eth1",
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


async def test_scapy_script(unet, r1repl, astepf):
    r2 = unet.hosts["r2"]

    await setup_policy_tun(unet, r1repl)
    # await setup_routed_tun(unet, r1repl)

    pktbin = os.path.join(SRCDIR, "genpkt.py")

    await astepf("Running genpkt.py script")
    p = r2.popen(
        [
            pktbin,
            "-v",
            "--local=10.0.1.3",
            "--remote=10.0.1.2",
            "--iface=eth1",
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
