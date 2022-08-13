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
import time

import common.testutil as testutil
import common.trexlib as trexlib
import pytest
from trex_stl_lib.api import STLClient

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


@pytest.fixture(scope="module", name="r2repl")
async def r2repl_(unet):
    return await console(unet, unet.hosts["r2"])


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
async def network_up(unet, r1repl, r2repl):
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]
    for r, repl in [(r1, r1repl), (r2, r2repl)]:
        repl.cmd_raises("sysctl -w net.ipv6.conf.all.autoconf=0")
        repl.cmd_raises("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        repl.cmd_raises("sysctl -w net.ipv4.ip_forward=1")
        repl.cmd_raises("ip link set lo up")

        for i in range(0, 3):
            repl.cmd_raises(f"ip link set eth{i} up")
            repl.cmd_raises(f"ip addr add {r.intf_addrs[f'eth{i}']} dev eth{i}")

    r1repl.cmd_raises("ip route add 12.0.0.0/24 via 10.0.1.3")
    r2repl.cmd_raises("ip route add 11.0.0.0/24 via 10.0.1.2")

    # trex local routes
    r1repl.cmd_raises("ip route add 16.0.0.0/8 via 11.0.0.1")
    r2repl.cmd_raises("ip route add 48.0.0.0/8 via 12.0.0.1")

    # trex remote routes
    r1repl.cmd_raises("ip route add 48.0.0.0/8 via 10.0.1.3")
    r2repl.cmd_raises("ip route add 16.0.0.0/8 via 10.0.1.2")

    # Pin the ARP entries
    logging.debug(r1repl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.3"))
    r1repl.cmd_raises(f"ip neigh change 10.0.1.3 dev {r1.net_intfs['net1']}")
    r2repl.cmd_raises(f"ip neigh change 10.0.1.2 dev {r1.net_intfs['net1']}")

    logging.debug(r1repl.cmd_raises("ping -w1 -i.2 -c1 11.0.0.1"))
    r1repl.cmd_raises("ip neigh change 11.0.0.1 dev eth2")

    logging.debug(r2repl.cmd_raises("ping -w1 -i.2 -c1 12.0.0.1"))
    r2repl.cmd_raises("ip neigh change 12.0.0.1 dev eth2")


async def test_net_up(unet, r1repl, r2repl):
    # r1 (qemu side) pings r2 (qemu side)
    logging.debug(r1repl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.3"))
    # r1 (qemu side) pings trex
    logging.debug(r1repl.cmd_raises("ping -w1 -i.2 -c1 11.0.0.1"))
    # r1 (qemu side) pings r2 (trex side)
    logging.debug(r1repl.cmd_raises("ping -w1 -i.2 -c1 12.0.0.3"))
    # r1 (qemu side) pings trex using routing
    logging.debug(r1repl.cmd_raises("ping -w1 -i.2 -c1 12.0.0.1"))

    # r2 (qemu side) pings r1 (qemu side)
    logging.debug(r2repl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.2"))
    # r2 (qemu side) pings trex
    logging.debug(r2repl.cmd_raises("ping -w1 -i.2 -c1 12.0.0.1"))
    # r2 (qemu side) pings r1 (trex side)
    logging.debug(r2repl.cmd_raises("ping -w1 -i.2 -c1 11.0.0.2"))
    # r2 (qemu side) pings trex
    logging.debug(r2repl.cmd_raises("ping -w1 -i.2 -c1 11.0.0.1"))


MODE = "mode iptfs"
USE_NULLNULL = True


async def setup_policy_tun(unet, r1repl, r2repl):
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]

    # for r, repl in [(r1, r1repl), (r2, r2repl)]:
    #     repl.cmd_raises("ip link set lo up")
    #     repl.cmd_raises("ip link set eth0 up")
    #     repl.cmd_status(f"""ip addr add {r.intf_addrs["eth0"]} dev eth0""")

    if USE_NULLNULL:
        rspi = spi_1to2 = 0xAAAAAA
        lspi = spi_2to1 = 0xBBBBBB
        sa_auth = 'auth digest_null ""'
        sa_enc = 'enc cipher_null ""'
    else:
        rspi = 0xAA
        lspi = 0xBB
        # sa_auth = "auth sha256 0x0123456789ABCDEF0123456789ABCDEF"
        # sa_enc = "enc aes 0xFEDCBA9876543210FEDCBA9876543210"
        sa_auth = ""
        sa_enc = (
            'aead "rfc4106(gcm(aes))" '
            "0x4a506a794f574265564551694d6537681A2B1A2B "
            "128"
            # "0x4a506a794f574265564551694d6537684a506a794f574265564551694d6537681A2B1A2B "
            # "256"
        )

    r1ipp = r1.intf_addrs["eth1"]
    r1ip = r1ipp.ip
    r1ipp = r1ipp.network
    r2ipp = r2.intf_addrs["eth1"]
    r2ip = r2ipp.ip
    r2ipp = r2ipp.network

    r1repl.cmd_status("ip x s deleteall")
    r1repl.cmd_status("ip x p deleteall")
    r2repl.cmd_status("ip x s deleteall")
    r2repl.cmd_status("ip x p deleteall")

    for r, repl in [(r1, r1repl), (r2, r2repl)]:
        #
        # SAs
        #
        repl.cmd_raises(
            f"ip xfrm state add src {r1ip} dst {r2ip} proto esp "
            f"spi {rspi} {MODE} {sa_auth} {sa_enc} "
            f"reqid 0x10"
        )
        repl.cmd_raises(
            f"ip xfrm state add src {r2ip} dst {r1ip} proto esp "
            f"spi {lspi} {MODE} {sa_auth} {sa_enc} "
            f"reqid 0x11"
        )

        #
        # Policy
        #
        for x1ipp, x2ipp in [
            ("10.0.1.0/24", "10.0.1.0/24"),  # router to router
            ("11.0.0.0/24", "12.0.0.0/24"),  # host to host
            ("16.0.0.0/8", "48.0.0.0/8"),  # host to host
        ]:
            for direction in ["dir out"] if r == r1 else ["dir fwd", "dir in"]:
                repl.cmd_raises(
                    f"ip xfrm policy add src {x1ipp} dst {x2ipp} {direction} "
                    f"tmpl src {r1ip} dst {r2ip} proto esp {MODE} "
                    f"reqid 0x10",
                    # " spi {rspi} "
                )
            for direction in ["dir out"] if r == r2 else ["dir fwd", "dir in"]:
                repl.cmd_raises(
                    f"ip xfrm policy add src {x2ipp} dst {x1ipp} {direction} "
                    f"tmpl src {r2ip} dst {r1ip} proto esp {MODE} "
                    f"reqid 0x11",
                    # " spi {lspi} "
                )


async def setup_routed_tun(unet, r1repl, r2repl):
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]

    reqid_1to2 = 8
    reqid_2to1 = 9

    spi_1to2 = 0xAA
    spi_2to1 = 0xBB
    # sa_auth = "auth sha256 0x0123456789ABCDEF0123456789ABCDEF"
    # sa_enc = 'enc cipher_null ""'
    sa_auth = ""
    sa_enc = (
        'aead "rfc4106(gcm(aes))" '
        "0x4a506a794f574265564551694d6537681A2B1A2B "
        "128"
        # "0x4a506a794f574265564551694d6537684a506a794f574265564551694d6537681A2B1A2B "
        # "256"
    )

    r1ipp = r1.intf_addrs["eth1"]
    r1ip = r1ipp.ip
    r1ipp = r1ipp.network
    r2ipp = r2.intf_addrs["eth1"]
    r2ip = r2ipp.ip
    r2ipp = r2ipp.network

    # Get rid of non-ipsec routes
    r1repl.cmd_raises("ip route del 12.0.0.0/24 via 10.0.1.3 || true")
    r1repl.cmd_raises("ip route del 48.0.0.0/8 via 10.0.1.3 || true")
    r2repl.cmd_raises("ip route del 11.0.0.0/24 via 10.0.1.2 || true")
    r2repl.cmd_raises("ip route del 16.0.0.0/8 via 10.0.1.2 || true")

    r1repl.cmd_status("ip x s deleteall")
    r1repl.cmd_status("ip x p deleteall")
    r2repl.cmd_status("ip x s deleteall")
    r2repl.cmd_status("ip x p deleteall")

    for r, repl in [(r1, r1repl), (r2, r2repl)]:
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

        # repl.cmd_raises(f"ip add vti0 local {lip} remote {rip} mode vti key 55")
        # repl.cmd_raises("sysctl -w net.ipv4.conf.vti0.disable_policy=1")
        # repl.cmd_raises("ip link set vti0 up")
        repl.cmd_raises("ip link add ipsec0 type xfrm dev eth1 if_id 55")
        # repl.cmd_raises("sysctl -w net.ipv4.conf.ipsec0.disable_policy=1")
        repl.cmd_raises("ip link set ipsec0 up")

        #
        # Policy
        #
        xdef = "0.0.0.0/0"

        direction = "dir out"
        repl.cmd_raises(
            f"ip xfrm policy add if_id 55 src {xdef} dst {xdef} {direction}"
            f" tmpl src {lip} dst {rip} proto esp spi {ospi} {MODE} reqid {oreqid}"
        )

        for direction in ["dir fwd", "dir in"]:
            repl.cmd_raises(
                f"ip xfrm policy add if_id 55 src {xdef} dst {xdef} {direction} "
                f"tmpl src {rip} dst {lip} proto esp spi {ispi} {MODE} reqid {ireqid}"
            )

    # Add ipsec0 based routes
    r1repl.cmd_raises("ip route add 12.0.0.0/24 dev ipsec0 src 10.0.1.2")
    r2repl.cmd_raises("ip route add 11.0.0.0/24 dev ipsec0 src 10.0.1.3")

    # trex remote routes
    r1repl.cmd_raises("ip route add 48.0.0.0/8 dev ipsec0 src 10.0.1.2")
    r2repl.cmd_raises("ip route add 16.0.0.0/8 dev ipsec0 src 10.0.1.3")


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


async def test_policy_small_pkt(unet, r1repl, r2repl, astepf):
    await setup_policy_tun(unet, r1repl, r2repl)

    args = testutil.Args(rate=convert_number("100K"), user_packet_size=40)

    # Some TREX test
    trex_ip = unet.hosts["trex"].intf_addrs["mgmt0"].ip
    c = STLClient(server=trex_ip, sync_timeout=10, async_timeout=10)
    c.connect()

    def get_streams(direction, imix_table, modeclass=None, statsclass=None, ipv6=False):
        # return trexlib.get_dynamic_imix_stream(direction, imix_table)
        return trexlib.get_static_streams(
            direction, imix_table, modeclass, statsclass, nstreams=args.connections
        )

    dutlist = []
    trex = None
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


async def test_policy_imix(unet, r1repl, r2repl, astepf):
    await setup_policy_tun(unet, r1repl, r2repl)

    args = testutil.Args(
        rate=convert_number("100K"), old_imix=True, unidirectional=True
    )

    # Some TREX test
    trex_ip = unet.hosts["trex"].intf_addrs["mgmt0"].ip
    c = STLClient(server=trex_ip, sync_timeout=10, async_timeout=10)
    c.connect()

    def get_streams(direction, imix_table, modeclass=None, statsclass=None, ipv6=False):
        # return trexlib.get_dynamic_imix_stream(direction, imix_table)
        return trexlib.get_static_streams(
            direction, imix_table, modeclass, statsclass, nstreams=args.connections
        )

    dutlist = []
    trex = None
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


# async def test_routed_tun_up(unet, r1repl, r2repl, astepf):
#     await setup_routed_tun(unet, r1repl, r2repl)
#     # Some TREX test
