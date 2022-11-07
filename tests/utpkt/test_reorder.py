# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# October 26 2022, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2022, LabN Consulting, L.L.C.
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
"Test of receipt of reordered packets."
import glob
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta

import pytest

# So gross.. but trex plays stupid games with embedded pkgs and path
SRCDIR = os.path.dirname(os.path.abspath(__file__))
trexlib = os.path.join(os.path.dirname(SRCDIR), "external_libs")

try:
    scapydir = glob.glob(trexlib + "/scapy*")[0]
    sys.path[0:0] = [scapydir]
except:
    pass

from common import iptfs
from common.config import create_scapy_sa_pair, setup_policy_tun, toggle_ipv6
from common.scapy import Interface, gen_pkts, send_recv_esp_pkts
from common.util import iptfs_payload_size
from munet.base import BaseMunet, comm_error
from scapy.config import conf
from scapy.layers.inet import ICMP, IP
from scapy.layers.ipsec import ESP
from scapy.sendrecv import AsyncSniffer, sendp, sniff, srp

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


def verify_inorder(recv_pkts, seqnos=None):
    if seqnos is None:
        # this code expects init_seq_num use for lists of packets.
        seqnos = list(range(1, len(recv_pkts) + 1))
    seqno = [pkt[ICMP].seq for pkt in recv_pkts]
    assert seqno == seqnos


async def init_seq_num(osa, tunpkts, iface="net1"):
    _, _, ippkts = send_recv_esp_pkts(osa, tunpkts[:1], iface=iface, net0only=True)
    verify_inorder(ippkts, [0])
    return tunpkts[1:]


async def _test_tun_drop_XtoYofN(
    unet, x, y, n, exceptevery=0, reorder_window=5, iface="net1", ping="10.0.0.1"
):
    """Drop consecutive ranges in segments of packets.

    Args:
        x: number of initial packets to send
        y: y - x are the dropped packets, so [1, x] and [y, n] are sent.
        n: total number of packets to send (including drops not sent)
        exceptevery: within the drop zone include every [exceptevery]^th packet.
        iface: the interface name to send on
        ping: the destination of the ping packet to send
        clump: (not used) the number of packets to send in a single system call.
    """
    await setup_policy_tun(
        unet,
        r1only=True,
        iptfs_opts=f"reorder-window {reorder_window} drop-time 50000 dont-frag",
    )

    # Generate encrypted IPTFS stream (count packets)
    count = n + 1

    mtu = 1500
    osa, sa = create_scapy_sa_pair(
        mtu=mtu, addr1=unet.tun_if.remote_addr, addr2=unet.tun_if.local_addr
    )

    #
    # Create encrypted packet stream without fragmentation
    #
    psize = iptfs_payload_size(mtu, True)
    opkts = await gen_pkts(unet, sa, ping=ping, mtu=mtu, psize=psize, count=count)
    tunpkts = iptfs.gen_encrypt_pktstream_pkts(sa, mtu, opkts, dontfrag=True)
    tunpkts = unet.tun_if.prep_pkts(tunpkts)

    # Send one packet in order to establish seq num.
    tunpkts = await init_seq_num(osa, tunpkts)

    #
    # Now drop various packets given by parameter x, y and n.
    #
    seqnos = list(range(1, count + 1))
    addts = []
    addss = []
    if exceptevery:
        # 3 of 10
        for i in range(x, y, exceptevery):
            if i == x:
                continue
            addts.append(tunpkts[i])
            addss.append(seqnos[i])

    tunpkts = tunpkts[: x - 1] + addts + tunpkts[y:]
    seqnos = seqnos[: x - 1] + addss + seqnos[y:]

    #
    # Send in tunnel and receive IP on downstream
    #
    r1 = unet.hosts["r1"]
    is_kvm = r1.is_kvm if hasattr(r1, "is_kvm") else False
    _, _, ippkts = send_recv_esp_pkts(osa, tunpkts, iface, faster=is_kvm, net0only=True)

    verify_inorder(ippkts, seqnos)


async def _test_tun_reverse_XofYxZ(
    unet, x, y, n, reorder_window=5, iface="net1", ping="10.0.0.1", clump=None
):
    """Reverse consecutive ranges in segments of packets.

    Args:
        x: number of elements to reverse
        y: run length of segment of elements to perform reverse in
        n: number of `y` length segments to send.
        iface: the interface name to send on
        ping: the destination of the ping packet to send
        clump: (not used) the number of packets to send in a single system call.
    """
    await setup_policy_tun(
        unet,
        r1only=True,
        iptfs_opts=f"reorder-window {reorder_window} drop-time 50000 dont-frag",
    )

    # Generate encrypted IPTFS stream (count packets.)
    count = y * n + 1

    mtu = 1500
    osa, sa = create_scapy_sa_pair(
        mtu=mtu, addr1=unet.tun_if.remote_addr, addr2=unet.tun_if.local_addr
    )

    #
    # Create encrypted packet stream without fragmentation.
    #
    psize = iptfs_payload_size(mtu, True)
    opkts = await gen_pkts(unet, sa, ping=ping, mtu=mtu, psize=psize, count=count)
    tunpkts = iptfs.gen_encrypt_pktstream_pkts(sa, mtu, opkts, dontfrag=True)
    tunpkts = unet.tun_if.prep_pkts(tunpkts)

    # Send one packet in order to establish seq num.
    tunpkts = await init_seq_num(osa, tunpkts)

    # we start the seqno from 1 bc we use 0 to prime the pump (initial seq num)
    iseqnos = list(range(1, count))
    seqnos = []
    drop = 0
    if x > reorder_window + 1:
        drop = x - (reorder_window + 1)

    #
    # Reverse x elements every y elements.
    #
    for i in range(0, count - 1, y):
        tunpkts[i : i + x] = reversed(tunpkts[i : i + x])
        seqnos.extend(iseqnos[i + drop : i + x])
    logging.debug("expected seqnos: %s", str(seqnos))

    #
    # Send in tunnel and receive IP from downstream
    #
    r1 = unet.hosts["r1"]
    is_kvm = r1.is_kvm if hasattr(r1, "is_kvm") else False

    _, _, ippkts = send_recv_esp_pkts(osa, tunpkts, iface, faster=is_kvm, net0only=True)

    verify_inorder(ippkts, seqnos)


# class TestReorderIPTFS4(_TestReorderIPTFS4):
#     """IPTFS Re-order tests"""

#     def test_tun_reorder_pathalogical_first_2of2(self):
#         self.vapi.cli("clear errors")
#         # Generate encrypted IPTFS stream (count packets)
#         count = 2
#         p = self.params[socket.AF_INET]


#         tunpkts = iptfs.gen_encrypt_pkts(
#             p.scapy_tun_sa,
#             self.tun_if,
#             src=p.remote_tun_if_host,
#             dst=self.pg1.remote_ip4,
#             count=count,
#         )
#         # To keep things easy, let's give it the first packet in order.
#         tunpkts.reverse()
#         # We expect the first packet to drop b/c we haven't established
#         # a starting sequence number and the second packet is passed it
#         # which establishes the starting point. This only happens when
#         # the first packet is out-of-order.
#         self.verify_decap_44(p, tunpkts, seqnos=[1])
#         # XXX check drop count for 1 here.

#     # def _test_tun_drop_1of5(self):
#     #     # We don't timeout our reordering window b/c we expect more packets
#     #     # always so this test won't work.

#     def test_tun_reorder_2of3(self):
#         self.vapi.cli("clear errors")
#         # Generate encrypted IPTFS stream (count packets)
#         count = 3
#         p = self.params[socket.AF_INET]
#         tunpkts = iptfs.gen_encrypt_pkts(
#             p.scapy_tun_sa,
#             self.tun_if,
#             src=p.remote_tun_if_host,
#             dst=self.pg1.remote_ip4,
#             count=count,
#         )
#         tunpkts = self.init_seq_num(p, tunpkts)
#         tunpkts.reverse()
#         self.verify_decap_44(p, tunpkts)

#     def test_tun_reorder_4of5(self):
#         self.vapi.cli("clear errors")
#         # Generate encrypted IPTFS stream (count packets)
#         count = 6
#         p = self.params[socket.AF_INET]
#         tunpkts = iptfs.gen_encrypt_pkts(
#             p.scapy_tun_sa,
#             self.tun_if,
#             src=p.remote_tun_if_host,
#             dst=self.pg1.remote_ip4,
#             count=count,
#         )
#         tunpkts = self.init_seq_num(p, tunpkts)
#         tunpkts.reverse()
#         self.verify_decap_44(p, tunpkts)

#     def test_tun_reorder_6of7_drop1(self):
#         self.vapi.cli("clear errors")
#         # Generate encrypted IPTFS stream (count packets)
#         count = 8
#         p = self.params[socket.AF_INET]
#         tunpkts = iptfs.gen_encrypt_pkts(
#             p.scapy_tun_sa,
#             self.tun_if,
#             src=p.remote_tun_if_host,
#             dst=self.pg1.remote_ip4,
#             count=count,
#         )
#         tunpkts = self.init_seq_num(p, tunpkts)
#         count = len(tunpkts)
#         tunpkts.reverse()

#         # Since it's reversed we should see the second packet get dropped
#         self.verify_decap_44(p, tunpkts, seqnos=[2, 3, 4, 5, 6, 7])


# async def test_tun_reverse_2of2x1(unet):
#     await _test_tun_reverse_XofYxZ(unet, 2, 2, 1)


# async def test_tun_reverse_2of2x2(unet):
#     await _test_tun_reverse_XofYxZ(unet, 2, 2, 2)


# async def test_tun_reverse_3of3x1(unet):
#     await _test_tun_reverse_XofYxZ(unet, 3, 3, 1)


# async def test_tun_reverse_3of3x2(unet):
#     await _test_tun_reverse_XofYxZ(unet, 3, 3, 2)


# async def test_tun_reverse_5of5(unet):
#     await _test_tun_reverse_XofYxZ(unet, 5, 5, 1)


# async def test_tun_reverse_5of5x30(unet):
#     await _test_tun_reverse_XofYxZ(unet, 5, 5, 30)


# async def test_tun_reverse_7of7(unet):
#     await _test_tun_reverse_XofYxZ(unet, 7, 7, 1)


# async def test_tun_reverse_7of7x30(unet):
#     await _test_tun_reverse_XofYxZ(unet, 7, 7, 30)

# # Generate more tests.

# def pytest_generate_tests(metafunc):
#     unet = BaseMunet.g_unet
#     for Y in range(2, 10):
#         for N in range(Y + 6, 17):
#             if Z == 0:
#                 name = "test_tun_drop_{}to{}of{}".format(2, Y, N)
#             else:
#                 name = "test_tun_drop_{}to{}of{}_exceptevery_{}".format(2, Y, N, Z)
#             metafunc.addcall(funcargs=dict(X=2, Y=Y, Z=Z)

for Z in range(0, 3):
    for Y in range(2, 6):
        for N in range(Y + 1, 13):
            if Z == 0:
                name = f"test_tun_drop_2to{Y}of{N}"
            else:
                name = f"test_tun_drop_2to{Y}of{N}_exceptevery_{Z}"
            exec(
                f"""
async def {name}(unet):
    return await _test_tun_drop_XtoYofN(unet, 2, {Y}, {N}, exceptevery={Z}, reorder_window=2)
            """
            )

# pylint: disable=exec-used,eval-used
for Z in range(0, 5):
    for Y in range(2, 10):
        for N in range(Y + 6, 17):
            if Z == 0:
                name = f"test_tun_drop_2to{Y}of{N}"
            else:
                name = f"test_tun_drop_2to{Y}of{N}_exceptevery_{Z}"
            exec(
                f"""
async def {name}(unet):
    return await _test_tun_drop_XtoYofN(unet, 2, {Y}, {N}, exceptevery={Z}, reorder_window=4)
            """
            )
