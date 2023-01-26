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

import ipaddress
import logging
import socket
import time

from common import iptfs

# from common.util import Timeout, chunkit
from common.util import get_intf_stats
from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.config import conf
from scapy.data import ETH_P_IPV6
from scapy.layers.inet import ICMP, IP
from scapy.layers.inet6 import (
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6NDOptSrcLLAddr,
    IPv6,
    _ICMPv6,
)
from scapy.layers.ipsec import ESP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.pton_ntop import inet_ntop, inet_pton
from scapy.sendrecv import AsyncSniffer, send, sendp, sr, sr1, srp, srp1
from scapy.utils6 import in6_getnsma, in6_getnsmac


def ppp(headline, pkt):
    return f"{headline}: {pkt.show(dump=True)}"


@conf.commands.register
def neighsol_(addr, src, iface, timeout=1, chainCC=0):
    """Sends and receive an ICMPv6 Neighbor Solicitation message

    This function sends an ICMPv6 Neighbor Solicitation message
    to get the MAC address of the neighbor with specified IPv6 address address.

    'src' address is used as source of the message. Message is sent on iface.
    By default, timeout waiting for an answer is 1 second.

    If no answer is gathered, None is returned. Else, the answer is
    returned (ethernet frame).
    """

    nsma = in6_getnsma(inet_pton(socket.AF_INET6, addr))
    d = inet_ntop(socket.AF_INET6, nsma)
    dm = in6_getnsmac(nsma)
    s = get_if_hwaddr(iface)
    p = Ether(dst=dm, src=s) / IPv6(dst=d, src=src, hlim=255)
    p /= ICMPv6ND_NS(tgt=addr)
    p /= ICMPv6NDOptSrcLLAddr(lladdr=s)
    for _ in range(0, 10):
        res = srp1(
            p,
            type=ETH_P_IPV6,
            iface=iface,
            timeout=timeout,
            verbose=False,
            chainCC=chainCC,
        )
        if not res:
            logging.info("IPv6 NDisc failed trying agian in 1s")
            time.sleep(1)

    return res


class Interface:
    "Interface class for interacting with scapy."

    def __init__(self, name, local_addr, remote_addr):
        self.name = name
        self.local_mac = get_if_hwaddr(name)
        self.local_addr = local_addr
        self.remote_addr = remote_addr
        self.is_ipv6 = ipaddress.ip_address(local_addr).version == 6

        self.remote_mac = self.get_remote_mac()
        logging.debug(
            "Interface: local %s mac %s remote %s mac %s",
            self.local_addr,
            self.local_mac,
            self.remote_addr,
            self.remote_mac,
        )

    def add_ether_encap(self, pkts):
        return [Ether(src=self.local_mac, dst=self.remote_mac) / x for x in pkts]

    def get_remote_mac(self):
        if self.is_ipv6:
            pkt = neighsol_(self.remote_addr, self.local_addr, self.name)
            return str(pkt[ICMPv6ND_NA].lladdr)
        ans = self.send_gratuitous_arp()
        return str(ans[0][1][ARP].hwsrc)

    def send_gratuitous_arp(self):
        # result = sr1(ARP(op=ARP.who_has, psrc='192.168.1.2', pdst='192.168.1.1'))
        pkt = Ether(src=self.local_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            hwsrc=self.local_mac, psrc=self.local_addr, pdst=self.remote_addr
        )
        ans, _ = srp(pkt, iface=self.name, verbose=False)
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
    sendp(p, iface=iface, verbose=False)


def filter_non_ip_pkts(pkts):
    def f(pkt):
        if IP in pkt:
            return True
        if IPv6 in pkt:
            # anything that's not ICMP is OK
            if pkt[IPv6].nh != 58:
                return True
            # Filter out most ICMPv6 packets
            if ICMPv6EchoRequest in pkt:
                return True
            if ICMPv6EchoReply in pkt:
                return True
        return False

    # See if we need to decap an IPTFS pkt stream
    if pkts and iptfs.IPTFSWithFrags in pkts[0]:
        pkts = iptfs.decap_frag_stream(pkts)
    inner_pkts = [x for x in pkts if f(x)]
    other_inner_pkts = [x for x in pkts if not f(x)]
    return inner_pkts, other_inner_pkts


def decrypt_iptfs_pkts(sa, encpkts):
    idx = 0
    pkts = []
    try:
        for idx, epkt in enumerate(encpkts):
            pkts.append(sa.decrypt_iptfs_pkt(epkt, prevpkts=pkts))
    except Exception as error:
        logging.error(
            "Exception decrypting esp pkt index %s: %s\n", idx, error, exc_info=True
        )
        raise
    return pkts


def decrypt_esp_pkts(sa, encpkts):
    idx = 0
    pkts = []
    try:
        for idx, epkt in enumerate(encpkts):
            pkts.append(sa.decrypt(epkt))
    except Exception as error:
        logging.error(
            "Exception decrypting esp pkt index %s: %s\n", idx, error, exc_info=True
        )
        raise
    return pkts


def gen_ippkts(  # pylint: disable=W0221
    src, dst, count=1, payload_size=54, payload_spread=0, inc=1, payload_sizes=None
):

    srcaddr = ipaddress.ip_address(src)
    if srcaddr.version == 4:
        ipcls = IP
        icmpcls = ICMP
    else:
        ipcls = IPv6
        icmpcls = ICMPv6EchoRequest

    if not payload_spread and not payload_sizes:
        return [
            ipcls(src=src, dst=dst) / icmpcls(seq=i) / Raw("X" * payload_size)
            for i in range(count)
        ]

    if not payload_spread:
        pslen = len(payload_sizes)
        for i in range(count):
            return [
                ipcls(src=src, dst=dst)
                / icmpcls(seq=i)
                / Raw("X" * payload_sizes[i % pslen])
                for i in range(count)
            ]
    else:
        # emptylen = len(IP(src=src, dst=dst) / ICMP(seq=1))
        pkts = []
        start = payload_size
        end = payload_spread
        psize = start if inc > 0 else end
        for i in range(count):
            pkts.append(ipcls(src=src, dst=dst) / icmpcls(seq=i) / Raw("X" * (psize)))
            psize += inc
            if inc > 0:
                if psize > end:
                    # wrap around
                    psize = start + (psize - end)
            else:
                if psize < end:
                    # wrap around
                    psize = end - (end - psize)
        return pkts


def gen_pkts(
    unet,
    sa,
    ping=None,
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
    pingaddr = ipaddress.ip_address(ping)
    if pingaddr.version == 4:
        inner_ip_overhead = len(IP() / ICMP(seq=1))
        local_addr = unet.tun_if.local_addr
    else:
        inner_ip_overhead = len(IPv6() / ICMPv6EchoRequest(seq=1))
        local_addr = unet.tun_if6.local_addr

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
            pcount = (pmaxsize - psize + 1) // (-pstep if pstep < 0 else pstep)
            if wrap:
                # should incorporate the remainder from division.
                pcount *= wrap
    else:
        pcount = count if count else 100
        pmaxsize = None

    logging.info(
        "GENERATING from %s to %s count %s step %s", psize, pmaxsize, pcount, pstep
    )
    opkts = gen_ippkts(
        local_addr,
        ping,
        payload_size=psize - inner_ip_overhead,
        payload_spread=pmaxsize - inner_ip_overhead if pmaxsize else pmaxsize,
        inc=pstep,
        count=pcount,
    )
    maxsz = max(len(x) for x in opkts)
    logging.info("GENERATED %s inner packets max size %s", len(opkts), maxsz)
    return opkts


def _nologf(*args, **kwargs):
    del args
    del kwargs


# XXX There's a few hard coded values in here that probably need cleaning up
def send_recv_esp_pkts(
    osa,
    encpkts,
    iface,
    chunksize=30,
    faster=False,
    net0only=False,
    process_recv_pkts=filter_non_ip_pkts,
    dolog=False,
):
    del chunksize

    tun_ipv6 = IPv6 in encpkts[0]

    if dolog:
        logf = logging.info
    else:
        logf = _nologf

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
                pkts.append(osa.decrypt_iptfs_pkt(esppkt, prevpkts=pkts))
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

    net0sniffer = AsyncSniffer(
        iface="net0", promisc=1, filter="icmp[0] == 0 or icmp6[0] == 129"
    )
    net0sniffer.start()

    if net0only:
        net1sniffer = None
    else:
        net1sniffer = AsyncSniffer(
            iface=iface,
            # prn=lambda x: print("-"),
            promisc=1,
            # filter=f"ip proto esp and ip[((ip[0]&0x0f)<<2):4]=={osa.spi}",
            # filter="ip proto 50 or ip6 proto 50",
            filter="dst host 10.0.1.3 or dst host fc00:0:0:1::3",
        )
        net1sniffer.start()

    # This sleep seems required or the sniffer misses initial packets!?
    time.sleep(0.5)

    logf("SENDING %s ipsec/iptfs packets", len(encpkts))

    outer_pkts = []
    decpkts = []

    # Really we want to check for kvm
    if faster or len(encpkts) <= 20:
        if Ether in encpkts[0]:
            x = sendp(encpkts, iface=iface, inter=0.001, verbose=False)
        else:
            x = send(encpkts, iface=iface, inter=0.001, verbose=False)
    else:
        if Ether in encpkts[0]:
            x = sendp(encpkts, iface=iface, inter=0.01, verbose=False)
        else:
            x = send(encpkts, iface=iface, inter=0.01, verbose=False)

    # nchunk = 0
    # for chunk in chunkit(encpkts, chunksize):
    #     # logf("SENDING gratiutous arp on %s", tun_if.name)
    #     # tun_if.send_gratuitous_arp()
    #     logf(
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
    #     logf("srp returns %s", pkts)

    #     _esppkts = get_esp_pkts(pkts[0])
    #     outer_pkts.extend(_esppkts)
    #     if len(_esppkts) == 0 and timeo is not None:
    #         if timeo.is_expired():
    #             logf("Ending chunking loop as no packets received (timeout)")
    #             raise TimeoutError()
    #         logf("Ending chunking loop as no packets received (break)")
    #         raise KeyboardInterrupt()
    #     _decpkts = process_esp_pkts(_esppkts, nchunk)
    #     decpkts.extend(_decpkts)

    # # If we arrive here w/o exceptions (from timeout or break)
    # # let's take another second to see if we have anymore packets coming.
    # timeout = 1
    # logf("Waiting %ss for final packets", timeout)
    # pkts = sniff(timeout=timeout, promisc=1, nofilter=1, iface=iface)
    # logf("Final sniff returns %s", pkts)

    # XXX improve this, sleep 2 seconds for things to flush
    time.sleep(0.5)

    net0results = net0sniffer.stop()
    net1results = net1sniffer.stop() if not net0only else []

    if tun_ipv6:
        # _esppkts = get_esp_pkts(pkts)
        pkts = [x[IPv6] for x in net1results if x.haslayer(ESP)]
        # XXX should use iface ip local addr
        _esppkts = [x for x in pkts if x.src != "fc00:0:0:1::3"]
    else:
        # _esppkts = get_esp_pkts(pkts)
        pkts = [x[IP] for x in net1results if x.haslayer(ESP)]
        # XXX should use iface ip local addr
        _esppkts = [x for x in pkts if x.src != "10.0.1.3"]

    logf("RECEIVED %s ipsec packets", len(_esppkts))

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
    logf("STATS for %s: RX %s TX %s", iface, nrxs - rxs, ntxs - txs)

    logf(
        "DECAP %s inner ICMP replies and %s other pkts from %s ipsec pkts",
        len(inner_pkts),
        len(other_inner_pkts),
        len(outer_pkts),
    )
    return inner_pkts, outer_pkts, net0results


def send_recv_pkts(
    ippkts,
    txiface,
    sa,
    rxiface,
    faster=False,
    process_recv_pkts=filter_non_ip_pkts,
    dolog=False,
    rxfilter="dst host 10.0.1.3 or dst host fc00:0:0:1::3",
    delay=0.5,
):
    if dolog:
        logf = logging.info
    else:
        logf = _nologf

    rxs, _, rxerr, _ = get_intf_stats(rxiface)
    assert max(rxerr) == 0, f"rxerr not 0, is {max(rxerr)}"
    _, txs, _, txerr = get_intf_stats(txiface)
    assert max(txerr) == 0, f"txerr not 0, is {max(txerr)}"

    logf("receiving %spackets on %s", "ipsec " if sa else "", rxiface)
    rxsniffer = AsyncSniffer(iface=rxiface, promisc=1, filter=rxfilter)
    rxsniffer.start()
    # This sleep seems required or the sniffer misses initial packets!?
    time.sleep(delay)

    logf("sending %s IP packets on %s", len(ippkts), txiface)
    if faster or len(ippkts) <= 20:
        if Ether in ippkts[0]:
            x = sendp(ippkts, iface=txiface, inter=0.001, verbose=False)
        else:
            x = send(ippkts, iface=txiface, inter=0.001, verbose=False)
    else:
        if Ether in ippkts[0]:
            x = sendp(ippkts, iface=txiface, inter=0.01, verbose=False)
        else:
            x = send(ippkts, iface=txiface, inter=0.01, verbose=False)

    # XXX improve this, sleep 0.5 seconds for things to flush
    time.sleep(delay)

    rxresults = rxsniffer.stop()
    if sa:
        pkts = [x[IPv6] if IPv6 in x else x[IP] for x in rxresults if ESP in x]
        decpkts = decrypt_esp_pkts(sa, pkts) if sa else pkts
    else:
        pkts = [x[IPv6] if IPv6 in x else x[IP] for x in rxresults]
        decpkts = pkts
    logf("received %s ipsec packets", len(pkts))

    if process_recv_pkts:
        inner_pkts, other_inner_pkts = process_recv_pkts(decpkts)
    else:
        inner_pkts, other_inner_pkts = decpkts, []

    nrxs, _, rxerr, _ = get_intf_stats(rxiface)
    assert max(rxerr) == 0, f"rxerr not 0, is {max(rxerr)}"
    _, ntxs, _, txerr = get_intf_stats(txiface)
    assert max(txerr) == 0, f"txerr not 0, is {max(txerr)}"
    logf("stats for tx-%s: %s rx-%s: %s", txiface, nrxs - rxs, rxiface, ntxs - txs)
    logf(
        "decapped %s inner IPv[46] packets and %s other pkts from %s ipsec pkts",
        len(inner_pkts),
        len(other_inner_pkts),
        len(pkts),
    )
    return inner_pkts, pkts
