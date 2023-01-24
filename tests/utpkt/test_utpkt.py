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
import logging
import os

import pytest
from common import iptfs
from common.config import _network_up, create_scapy_sa_pair, setup_policy_tun
from common.scapy import Interface, gen_pkts, send_recv_esp_pkts
from scapy.config import conf
from scapy.layers.inet import ICMP
from scapy.layers.inet6 import ICMPv6EchoReply

# from munet.cli import async_cli

# All tests are coroutines
pytestmark = pytest.mark.asyncio

SRCDIR = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module", autouse=True)
async def network_up(unet, pytestconfig):
    await _network_up(unet, r1only=True, ipv6=unet.ipv6_enable)

    #
    # Scapy settings
    #
    # Reload now that unet is in a new namespace
    conf.ifaces.reload()
    conf.route.resync()

    # Defaults to 64k which leads to lots of packet drops on sniffers
    conf.bufsize = 2**18

    # conf.iface = "net1"
    unet.tun_if = Interface("net1", local_addr="10.0.1.3", remote_addr="10.0.1.2")
    if unet.ipv6_enable:
        unet.tun_if6 = Interface(
            "net1", local_addr="fc00:0:0:1::3", remote_addr="fc00:0:0:1::2"
        )

    # Need to deal with ARP entry not going away on DUT since we won't answer as scapy
    r1 = unet.hosts["r1"]
    r1.cmd_raises("ping -c1 10.0.1.3")

    r1dev = r1.net_intfs["net1"]
    r1.conrepl.cmd_nostatus(f"ip neigh change {unet.tun_if.local_addr} dev {r1dev}")
    # r1.conrepl.cmd_nostatus(f"ip neigh del {tun_if.local_addr} dev {r1dev}")
    # unet.hosts["r1"].conrepl.cmd_raises(
    #     f"ip neigh add {tun_if.local_addr} lladdr {tun_if.local_mac} "
    #     f"dev {dev} nud permanent"
    # )

    # Remove IP from our scapy node
    unet.cmd_raises("ip addr del 10.0.1.3/24 dev net1")
    # unet.cmd_raises("ip -6 addr del fc00:0:0:1::3/64 dev net1")


#                             192.168.0.0/24
#   --+-------------------+------ mgmt0 -------+------
#     | .1                | .2                 | .254
#   +----+              +----+              +------+
#   | h1 | --- net0 --- | r1 | --- net1 --- | unet |
#   +----+ .1        .2 +----+ .2        .3 +------+
#          10.0.0.0/24         10.0.1.0/24


async def test_net_up(unet, pytestconfig):
    ipv6 = pytestconfig.getoption("--enable-ipv6", False)
    r1repl = unet.hosts["r1"].conrepl
    h1 = unet.hosts["h1"]

    # h1 pings r1 (qemu side)
    logging.debug(h1.cmd_raises("ping -w1 -i.2 -c1 10.0.0.2"))
    # h1 pings r1 (other side)
    logging.debug(h1.cmd_raises("ping -w1 -i.2 -c1 10.0.1.2"))
    # r1 (qemu side) pings h1
    logging.debug(r1repl.cmd_raises("ping -w1 -i.2 -c1 10.0.0.1"))

    if ipv6:
        # h1 pings r1 (qemu side)
        logging.debug(h1.cmd_raises("ping -c1 fc00::2"))
        # h1 pings r1 (other side)
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:1::2"))
        # r1 (qemu side) pings h1
        logging.debug(r1repl.cmd_raises("ping -c1 fc00::1"))

    # Make sure we can ping the ssh interface
    # h1.cmd_raises("ping -w1 -i.2 -c1 192.168.0.2")
    # unet.cmd_raises("ping -w1 -i.2 -c1 192.168.0.2")
    # commander.cmd_raises("ping -w1 -i.2 -c1 192.168.0.2")
    # unet.hosts["r1"].cmd_raises("ping -w1 -i.2 -c1 192.168.0.2")


def send_recv_pkts(osa, encpkts, iface, chunksize=30, faster=False, ipv6=False):
    def process_pkts(decpkts):
        _pkts = iptfs.decap_frag_stream(decpkts)
        # Greb echo replies.
        if ipv6:
            inner_pkts = [x for x in _pkts if ICMPv6EchoReply in x]
            other_inner_pkts = [x for x in _pkts if ICMPv6EchoReply not in x]
        else:
            inner_pkts = [x for x in _pkts if x.haslayer(ICMP) and x[ICMP].type == 0]
            other_inner_pkts = [
                x for x in _pkts if not x.haslayer(ICMP) or x[ICMP].type != 0
            ]
        return inner_pkts, other_inner_pkts

    return send_recv_esp_pkts(
        osa,
        encpkts,
        iface,
        chunksize=chunksize,
        faster=faster,
        process_recv_pkts=process_pkts,
        dolog=True,
    )


def prep_gen_pkts(
    unet,
    remote_addr=None,
    mtu=1500,
    df=False,
    ipv6=False,
    tun_ipv6=False,
    sa_seq=None,
    **kwargs,
):
    tun_if = unet.tun_if6 if tun_ipv6 else unet.tun_if

    if remote_addr is None:
        remote_addr = "fc00::1" if ipv6 else "10.0.0.1"
    # local_addr = "fc00:0:0:1::3" if ipv6 else "10.0.1.3"

    seq2to1 = 0 if sa_seq is None else sa_seq
    osa, sa = create_scapy_sa_pair(
        mtu=mtu,
        addr1=tun_if.remote_addr,
        addr2=tun_if.local_addr,
        seq_num2=seq2to1,
        tun_ipv6=tun_ipv6,
    )

    #
    # Create encrypted packet stream with fragmentation
    #
    opkts = gen_pkts(unet, sa, mtu=mtu, ping=remote_addr, **kwargs)
    return tun_if, osa, sa, opkts


def analyze_pkts(opkts, pkts, net0pkts, nofail):
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


async def gen_pkt_test(
    unet,
    addr=None,
    mtu=1500,
    df=False,
    iface="net1",
    nofail=False,
    ipv6=False,
    tun_ipv6=False,
    sa_seq=None,
    **kwargs,
):
    #
    # Generate packets
    #
    tun_if, osa, sa, opkts = prep_gen_pkts(
        unet, addr, mtu, df, ipv6, tun_ipv6, sa_seq, **kwargs
    )
    encpkts = iptfs.gen_encrypt_pktstream_pkts(sa, mtu, opkts, dontfrag=df)
    encpkts = tun_if.add_ether_encap(encpkts)

    #
    # Send / receive packets
    #
    is_kvm = unet.hosts["r1"].is_kvm if hasattr(unet.hosts["r1"], "is_kvm") else False
    is_kvm = False
    pkts, _, net0pkts = send_recv_pkts(osa, encpkts, iface, faster=is_kvm, ipv6=ipv6)

    #
    # Analyze results
    #
    return analyze_pkts(opkts, pkts, net0pkts, nofail)


# @pytest.mark.parametrize("ipv6", [False, True])
# async def test_primethepump(unet, astepf, ipv6):
#     await setup_policy_tun(unet, r1only=True, iptfs_opts="dont-frag", ipv6=ipv6)
#     await astepf("Prior to gen_pkt_test")
#     await gen_pkt_test(unet, psize=0, count=1, ipv6=ipv6)
#     # await gen_pkt_test(unet, psize=1400, pmax=1438, pstep=1, ipv6=ipv6)


@pytest.mark.parametrize("tun_ipv6", [False, True])
@pytest.mark.parametrize("ipv6", [False, True])
async def test_spread_recv_frag(unet, astepf, ipv6, tun_ipv6, pytestconfig):
    await setup_policy_tun(unet, r1only=True, ipv6=ipv6, tun_ipv6=tun_ipv6)

    # Priming the pump screws up the sequence numbering
    await astepf("Prime the pump")
    await gen_pkt_test(unet, psize=0, count=1, ipv6=ipv6, tun_ipv6=tun_ipv6)

    await astepf("Prior to gen_pkt_test")
    await gen_pkt_test(unet, psize=0, pstep=11, ipv6=ipv6, sa_seq=1, tun_ipv6=tun_ipv6)
    # await gen_pkt_test(unet, psize=0, pstep=1, ipv6=ipv6, sa_seq=1, tun_ipv6=tun_ipv6)


@pytest.mark.parametrize("tun_ipv6", [False, True])
@pytest.mark.parametrize("ipv6", [False, True])
async def test_spread_recv_frag_toobig_reply(unet, astepf, ipv6, tun_ipv6):
    await setup_policy_tun(
        unet, r1only=True, iptfs_opts="dont-frag", ipv6=ipv6, tun_ipv6=tun_ipv6
    )

    await astepf("Prior to too big gen_pkt_test")
    toobig = 1423 if tun_ipv6 else 1443
    npkts, nopkts, nnet0pkts = await gen_pkt_test(
        unet,
        psize=toobig - 1,
        pmax=toobig,
        pstep=1,
        nofail=True,
        ipv6=ipv6,
        tun_ipv6=tun_ipv6,
    )
    # one echo reply is too big
    assert npkts == 1 and nnet0pkts == 2 and nopkts == 2


@pytest.mark.parametrize("ipv6", [False, True])
async def test_recv_frag(unet, astepf, ipv6):
    await setup_policy_tun(unet, r1only=True, iptfs_opts="init-delay 10000", ipv6=ipv6)
    await astepf("Prior to gen_pkt_test")
    await gen_pkt_test(unet, psize=411, mtu=500, pstep=1, count=2, ipv6=ipv6)


@pytest.mark.parametrize("ipv6", [False, True])
async def test_small_pkt_agg(unet, astepf, ipv6):
    await setup_policy_tun(unet, r1only=True, iptfs_opts="dont-frag", ipv6=ipv6)
    await astepf("Prior to gen_pkt_test")
    await gen_pkt_test(unet, count=80, ipv6=ipv6)


@pytest.mark.parametrize("tun_ipv6", [False, True])
@pytest.mark.parametrize("ipv6", [False, True])
async def test_recv_runt(unet, astepf, ipv6, tun_ipv6):
    await setup_policy_tun(unet, r1only=True, iptfs_opts="", ipv6=ipv6)
    await astepf(f"Prior to gen_pkt_test, ipv6: {ipv6}")
    await gen_pkt_test(
        unet, psize=1421 if tun_ipv6 else 1441, mtu=1500, count=3, ipv6=ipv6
    )


# @pytest.mark.parametrize("ipv6", [False, True])
# async def _test_recv_runt2(unet, astepf, ipv6):
#     await setup_policy_tun(unet, r1only=True, iptfs_opts="", ipv6=ipv6)
#     await astepf("Prior to gen_pkt_test")
#     await gen_pkt_test(
#         unet, psize=1441, pmax=1451, mtu=1500, count=10, pstep=-1, ipv6=ipv6
#     )
