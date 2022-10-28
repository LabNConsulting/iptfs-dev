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
import time

# from common.util import Timeout, chunkit
from common.util import get_intf_stats
from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.config import conf
from scapy.layers.inet import ICMP, IP
from scapy.layers.ipsec import ESP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.sendrecv import AsyncSniffer, sendp, srp


def ppp(headline, pkt):
    return f"{headline}: {pkt.show(dump=True)}"


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
            hwsrc=self.local_mac, psrc=self.local_addr, pdst=self.remote_addr
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
            IP(src=src, dst=dst) / ICMP(seq=i) / Raw("X" * payload_size)
            for i in range(count)
        ]

    if not payload_spread:
        pslen = len(payload_sizes)
        for i in range(count):
            return [
                IP(src=src, dst=dst) / ICMP(seq=i) / Raw("X" * payload_sizes[i % pslen])
                for i in range(count)
            ]
    else:
        # emptylen = len(IP(src=src, dst=dst) / ICMP(seq=1))
        pkts = []
        start = payload_size
        end = payload_spread
        psize = start
        for i in range(count):
            pkts.append(IP(src=src, dst=dst) / ICMP(seq=i) / Raw("X" * (psize)))
            psize += inc
            if psize > end:
                # wrap around
                psize = start + (psize - end)
        return pkts


async def gen_pkts(
    unet,
    sa,
    ping="10.0.0.1",
    mtu=1500,
    psize=0,
    pstep=0,
    pmax=0,
    count=0,
    wrap=False,
):
    """Generate IPCMP packet stream according to various parameters.

    Args:
        mtu: the size of the outer IPTFS packet.
        psize: size of the inner packet including the IP header, or
            0 for minimum.
        pstep: if non-zero indicates each packet should increse in size
            byte this size, up to large enough to fill the maximum
            size.
        pmax: the size to `pstep` to, or zero to fill to `mtu` size
            outer packet. This determines the maximum size.
        count: the number of packets to send. If zero then pstep should
            be set and the count will be enough to reach the maximum size.
        wrap: the number of times to repeat `pstep`ing to the maximum size.

    """
    inner_ip_overhead = len(IP() / ICMP(seq=1))

    psize = max(psize, inner_ip_overhead)
    if pstep:
        if pmax:
            pmaxsize = max(pmax, psize)
        else:
            pmaxsize = mtu - sa.get_ipsec_overhead()
            logging.info("setting pmaxsize to %s", pmaxsize)

        if count:
            pcount = count
        else:
            # Walk spread one time
            pcount = (pmaxsize - psize + 1 + pstep - 1) // pstep
            if wrap:
                pcount *= wrap
    else:
        pcount = count if count else 100
        pmaxsize = None

    logging.info(
        "GENERATING from %s to %s count %s step %s", psize, pmaxsize, pcount, pstep
    )
    opkts = gen_ippkts(
        unet.tun_if.local_addr,
        ping,
        payload_size=psize - inner_ip_overhead,
        payload_spread=pmaxsize - inner_ip_overhead if pmaxsize else pmaxsize,
        inc=pstep,
        count=pcount,
    )
    maxsz = max(len(x) for x in opkts)
    logging.info("GENERATED %s inner packets max size %s", len(opkts), maxsz)
    return opkts


# XXX There's a few hard coded values in here that probably need cleaning up
def send_recv_esp_pkts(
    osa,
    encpkts,
    iface,
    chunksize=30,
    faster=False,
    net0only=False,
    process_recv_pkts=None,
):
    del chunksize

    rxs, txs, rxerr, txerr = get_intf_stats(iface)
    assert max(rxerr) == 0, f"rxerr not 0, is {max(rxerr)}"
    assert max(txerr) == 0, f"txerr not 0, is {max(txerr)}"

    # def get_esp_pkts(pkts):
    #     rawpkts = (x.answer for x in pkts)
    #     pkts = [x[IP] for x in rawpkts if x.haslayer(ESP)]
    #     logging.info("RECEIVED %s ipsec packets", len(pkts))
    #     return pkts

    def process_esp_pkts(esppkts, nchunk):
        idx = 0
        pkts = []
        try:
            for idx, esppkt in enumerate(esppkts):
                pkts.append(osa.decrypt(esppkt))
        except Exception as error:
            logging.error(
                "Exception decrypt recv ESP pkts index %s chunk %s: %s\n",
                idx,
                nchunk,
                error,
                exc_info=True,
            )
            raise
        return pkts

    net0sniffer = AsyncSniffer(iface="net0", promisc=1, filter="icmp[0] == 0")
    net0sniffer.start()

    if net0only:
        net1sniffer = None
    else:
        net1sniffer = AsyncSniffer(
            iface=iface,
            # prn=lambda x: print("-"),
            promisc=1,
            # filter=f"ip proto esp and ip[((ip[0]&0x0f)<<2):4]=={osa.spi}",
            filter="dst host 10.0.1.3",
        )
        net1sniffer.start()

    # This sleep seems required or the sniffer misses initial packets!?
    time.sleep(1)

    logging.info("SENDING %s ipsec/iptfs packets", len(encpkts))

    outer_pkts = []
    decpkts = []

    # Really we want to check for kvm
    if faster or len(encpkts) <= 20:
        sendp(encpkts, iface=iface, inter=0.001)
    else:
        sendp(encpkts, iface=iface, inter=0.01)

    # nchunk = 0
    # for chunk in chunkit(encpkts, chunksize):
    #     # logging.info("SENDING gratiutous arp on %s", tun_if.name)
    #     # tun_if.send_gratuitous_arp()
    #     logging.info(
    #          "sending chunk %s with %s ipsec/iptfs packets", nchunk, len(chunk)
    #     )

    #     nchunk += 1
    #     timeout = 10
    #     timeo = Timeout(timeout)
    #     pkts = srp(
    #         chunk,
    #         verbose=0,
    #         timeout=timeout,
    #         promisc=1,
    #         nofilter=1,
    #         iface=iface,
    #         inter=0.05,
    #         chainCC=True,  # pass up ^C
    #     )
    #     logging.info("srp returns %s", pkts)

    #     _esppkts = get_esp_pkts(pkts[0])
    #     outer_pkts.extend(_esppkts)
    #     if len(_esppkts) == 0 and timeo is not None:
    #         if timeo.is_expired():
    #             logging.info("Ending chunking loop as no packets received (timeout)")
    #             raise TimeoutError()
    #         logging.info("Ending chunking loop as no packets received (break)")
    #         raise KeyboardInterrupt()
    #     _decpkts = process_esp_pkts(_esppkts, nchunk)
    #     decpkts.extend(_decpkts)

    # # If we arrive here w/o exceptions (from timeout or break)
    # # let's take another second to see if we have anymore packets coming.
    # timeout = 1
    # logging.info("Waiting %ss for final packets", timeout)
    # pkts = sniff(timeout=timeout, promisc=1, nofilter=1, iface=iface)
    # logging.info("Final sniff returns %s", pkts)

    # XXX improve this, sleep 2 seconds for things to flush
    time.sleep(2)

    net0results = net0sniffer.stop()
    net1results = net1sniffer.stop() if not net0only else []

    # _esppkts = get_esp_pkts(pkts)
    pkts = [x[IP] for x in net1results if x.haslayer(ESP)]
    # XXX should use iface ip local addr
    _esppkts = [x for x in pkts if x.src != "10.0.1.3"]
    logging.info("RECEIVED %s ipsec packets", len(_esppkts))

    outer_pkts.extend(_esppkts)
    if _esppkts:
        _decpkts = process_esp_pkts(_esppkts, -1)
        decpkts.extend(_decpkts)

    if process_recv_pkts:
        inner_pkts, other_inner_pkts = process_recv_pkts(decpkts)
    else:
        inner_pkts, other_inner_pkts = decpkts, []

    nrxs, ntxs, rxerr, txerr = get_intf_stats(iface)
    assert max(rxerr) == 0, f"rxerr not 0, is {max(rxerr)}"
    assert max(txerr) == 0, f"txerr not 0, is {max(txerr)}"
    logging.info("STATS for %s: RX %s TX %s", iface, nrxs - rxs, ntxs - txs)

    logging.info(
        "DECAP %s inner ICMP replies and %s other pkts from %s ipsec pkts",
        len(inner_pkts),
        len(other_inner_pkts),
        len(outer_pkts),
    )
    return inner_pkts, outer_pkts, net0results
