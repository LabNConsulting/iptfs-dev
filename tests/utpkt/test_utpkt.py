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
# pylint: disable=wrong-import-position
"Unit tests utilizign scapy"
import glob
import logging
import os
import subprocess
import sys

import pytest
from common import iptfs, util
from common.config import create_scapy_sa_pair, setup_policy_tun, toggle_ipv6
from common.scapy import Interface, gen_pkts, send_recv_esp_pkts
from munet.base import comm_error
from scapy.config import conf
from scapy.layers.inet import ICMP

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

    #
    # Scapy settings
    #

    # Defaults to 64k which leads to lots of packet drops on sniffers
    conf.bufsize = 2**18

    # conf.iface = "net1"
    unet.tun_if = Interface("net1", local_addr="10.0.1.3", remote_addr="10.0.1.2")


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


def decrypt_decap_iptfs_pkts(osa, encpkts):
    """Decrypt a list of packets and then process resulting IPTFS stream"""
    idx = 0
    pkts = []
    try:
        for idx, esppkt in enumerate(encpkts):
            pkts.append(osa.decrypt(esppkt))
    except Exception as error:
        logging.error(
            "Exception decrypt recv ESP pkts index %s: %s\n",
            idx,
            error,
            exc_info=True,
        )
        raise
    return iptfs.decap_frag_stream(pkts)


def send_recv_iptfs_pkts(osa, encpkts, iface, chunksize=30, faster=False):
    def process_pkts(decpkts):
        _pkts = iptfs.decap_frag_stream(decpkts)
        # Greb echo replies.
        inner_pkts = [x for x in _pkts if x.haslayer(ICMP) and x[ICMP].type == 0]
        other_inner_pkts = [
            x for x in _pkts if not x.haslayer(ICMP) or x[ICMP].type != 0
        ]
        return inner_pkts, other_inner_pkts

    return send_recv_esp_pkts(osa, encpkts, iface, chunksize, faster, process_pkts)


async def gen_pkt_test(
    unet,
    ping="10.0.0.1",
    mtu=1500,
    df=False,
    iface="net1",
    nofail=False,
    **kwargs,
):
    osa, sa = create_scapy_sa_pair(
        mtu=mtu, addr1=unet.tun_if.remote_addr, addr2=unet.tun_if.local_addr
    )

    #
    # Create encrypted packet stream with fragmentation
    #
    opkts = await gen_pkts(unet, sa, mtu=mtu, ping=ping, **kwargs)
    encpkts = iptfs.gen_encrypt_pktstream_pkts(sa, mtu, opkts, dontfrag=df)
    encpkts = unet.tun_if.prep_pkts(encpkts)

    #
    # Send and receive pkts
    #
    r1 = unet.hosts["r1"]
    is_kvm = r1.is_kvm if hasattr(r1, "is_kvm") else False
    pkts, _, net0pkts = send_recv_iptfs_pkts(osa, encpkts, iface, faster=is_kvm)

    #
    # Analyze results
    #
    nnet0pkts = len(net0pkts)
    npkts = len(pkts)
    nopkts = len(opkts)
    if nnet0pkts != nopkts:
        logging.error("host replies (%s) != sent pings (%s)", nnet0pkts, nopkts)
    if npkts != nopkts and not nofail:
        logging.error("received replies (%s) != sent pings (%s)", npkts, nopkts)
    elif nofail:
        logging.debug("received replies (%s) != sent pings (%s)", npkts, nopkts)

    if not nofail:
        assert (
            nnet0pkts == nopkts and npkts == nopkts
        ), f"inner packets, sent {nopkts} host replies {nnet0pkts} received {npkts}"
    return npkts, nopkts, nnet0pkts


async def _gen_pkt_test(unet, astepf, expected=None, **kwargs):
    pktbin = os.path.join(SRCDIR, "genpkt.py")

    if expected is None:
        expected = kwargs["count"]

    args = [f"--{x}={y}" for x, y in kwargs.items()]
    await astepf(f"Running genpkt.py script: {' '.join(args)}")
    p = unet.popen(
        [pktbin, "-v", "--iface=net1", *args],
        stderr=subprocess.STDOUT,
    )
    try:
        _ = util.wait_output(p, "STARTING")

        m = util.wait_output(p, r"DECAP (\d+) inner packets")
        ndecap = int(m.group(1))
        assert (
            ndecap == expected
        ), f"Wrong number ({ndecap}, expected {expected}) return IP packets"

        _ = util.wait_output(p, "FINISH")

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


async def test_spread_recv_frag(unet, astepf):
    await setup_policy_tun(unet, r1only=True, iptfs_opts="dont-frag")
    await astepf("Prior to gen_pkt_test")
    await gen_pkt_test(unet, psize=0, pstep=1)
    # await gen_pkt_test(unet, psize=1400, pmax=1438, pstep=1)


async def test_spread_recv_frag_toobig_reply(unet, astepf):
    await setup_policy_tun(unet, r1only=True, iptfs_opts="dont-frag")
    await astepf("Prior to gen_pkt_test")
    npkts, nopkts, nnet0pkts = await gen_pkt_test(
        unet, psize=1442, pmax=1443, pstep=1, nofail=True
    )
    # one echo reply is too big
    assert npkts == 1 and nnet0pkts == 2 and nopkts == 2


async def test_recv_frag(unet, astepf):
    await setup_policy_tun(unet, r1only=True, iptfs_opts="dont-frag")
    await astepf("Prior to gen_pkt_test")
    await gen_pkt_test(unet, psize=411, mtu=500, pstep=1, count=2)


async def test_small_pkt_agg(unet, astepf):
    await setup_policy_tun(unet, r1only=True, iptfs_opts="dont-frag")
    await astepf("Prior to gen_pkt_test")
    await gen_pkt_test(unet, count=80)
