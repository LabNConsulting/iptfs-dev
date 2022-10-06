# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# October 6 2022, Christian Hopps <chopps@labn.net>
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
"Classes and functions for using scapy in tests."

import logging

from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.config import conf
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.sendrecv import sendp, srp


class Interface:
    "Interface class for interacting with scapy."
    def __init__(self, name, local_addr, remote_addr):
        self.name = name
        self.local_mac = get_if_hwaddr(name)
        self.local_addr = local_addr
        self.remote_addr = remote_addr

        ans = self.send_gratuitous_arp()
        self.remote_mac = ans[0][1][ARP].hwsrc
        logging.debug(
            "Interface: local %s mac %s remote %s mac %s",
            self.local_addr,
            self.local_mac,
            self.remote_addr,
            self.remote_mac,
        )

    def prep_pkts(self, pkts):
        npkts = []
        for pkt in pkts:
            npkts.append(Ether(src=self.local_mac, dst=self.remote_mac) / pkt)
        return npkts

    def send_gratuitous_arp(self):
        # result = sr1(ARP(op=ARP.who_has, psrc='192.168.1.2', pdst='192.168.1.1'))
        pkt = Ether(src=self.local_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            psrc=self.local_addr, pdst=self.remote_addr
        )
        ans, _ = srp(pkt, iface=self.name)
        return ans


def send_gratuitous_arp(ip=None, mac=None, iface=None):
    if iface is None:
        iface = conf.iface
    if mac is None:
        mac = get_if_hwaddr(iface)
    if ip is None:
        ip = get_if_addr(iface)
    BCAST_MAC = "ff:ff:ff:ff:ff:ff"
    arp = ARP(psrc=ip, hwsrc=mac, pdst=ip)
    p = Ether(dst=BCAST_MAC) / arp
    logging.info("Sending gratiutous ARP: %s", p.summary())
    sendp(p, iface=iface)


def gen_ippkts(  # pylint: disable=W0221
    src, dst, count=1, payload_size=54, payload_spread=0, inc=1, payload_sizes=None
):
    if not payload_spread and not payload_sizes:
        return [
            IP(src=src, dst=dst) / ICMP(seq=i + 1) / Raw("X" * payload_size)
            for i in range(count)
        ]

    if not payload_spread:
        pslen = len(payload_sizes)
        for i in range(count):
            return [
                IP(src=src, dst=dst)
                / ICMP(seq=i + 1)
                / Raw("X" * payload_sizes[i % pslen])
                for i in range(count)
            ]
    else:
        # emptylen = len(IP(src=src, dst=dst) / ICMP(seq=1))
        pkts = []
        start = payload_size
        end = payload_spread
        psize = start
        for i in range(count):
            pkts.append(IP(src=src, dst=dst) / ICMP(seq=i + 1) / Raw("X" * (psize)))
            psize += inc
            if psize > end:
                # wrap around
                psize = start + (psize - end)
        return pkts
