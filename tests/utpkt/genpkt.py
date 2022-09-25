#!/usr/bin/env python3
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# June 3 2022, Christian Hopps <chopps@labn.net>
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

import argparse
import binascii
import logging
import socket
import sys
from subprocess import check_output

from common import iptfs
from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.config import conf
from scapy.layers.inet import ICMP, IP
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import ESP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.sendrecv import sendp, srp


USE_GCM = True


# 3: eth1@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
#         qdisc noqueue state UP mode DEFAULT group default qlen 1000
#     link/ether 6a:a1:3f:28:7b:fb brd ff:ff:ff:ff:ff:ff link-netnsid 0
#     RX:  bytes packets errors dropped  missed   mcast
#        1015906     895      0       0       0       0
#     TX:  bytes packets errors dropped carrier collsns
#        1420434     943      0       0       0       0


def get_intf_stats(intf):
    try:
        output = check_output(f"ip -s link show {intf}", shell=True, text=True).strip()
        lines = output.split("\n")
        rxstats = [int(x) for x in lines[3].strip().split()]
        txstats = [int(x) for x in lines[5].strip().split()]
        return rxstats[1], txstats[1], rxstats[2:-1], txstats[2:-1]
    except Exception as error:
        logging.error("Got error getting stats: %s", error)
        raise


class Interface:
    def __init__(self, name, local_addr, remote_addr):
        self.name = name
        self.local_mac = get_if_hwaddr(name)
        self.local_addr = local_addr
        self.remote_addr = remote_addr

        ans = self.send_gratuitous_arp()
        self.remote_mac = ans[0][1][ARP].hwsrc
        logging.debug("Interface: %s remote mac is %s", remote_addr, self.remote_mac)

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


class IPsecIPv4Params:

    addr_type = socket.AF_INET
    addr_any = "0.0.0.0"
    addr_bcast = "255.255.255.255"
    addr_len = 32
    is_ipv6 = 0

    def __init__(self):
        self.remote_tun_if_host = "10.0.1.2"
        self.linux_tun_sa_id = 0x10
        self.linux_tun_sa = None
        self.scapy_tun_sa_id = 0x11
        self.scapy_tun_sa = None
        if USE_GCM:
            self.linux_tun_spi = 0xAA
            self.scapy_tun_spi = 0xBB

            self.crypt_algo = "AES-GCM"  # scapy name
            self.crypt_key = binascii.unhexlify("4a506a794f574265564551694d653768")
            self.crypt_salt = binascii.unhexlify("1A2B1A2B")
            self.auth_algo = None
            self.auth_key = ""
            self.salt = 0x1A2B1A2B
        else:
            self.linux_tun_spi = 0xAAAA
            self.scapy_tun_spi = 0xBBBB
            self.crypt_algo = "NULL"  # scapy name
            self.crypt_key = ""
            self.auth_algo = "HMAC-SHA1-96"  # scapy name
            self.auth_key = binascii.unhexlify(
                "4339314b55523947594d6d3547666b45764e6a58"
            )
            self.crypt_salt = ""
            self.salt = None

        self.flags = 0
        self.nat_header = None


def config_tun_params(p, tun_if, use_esn=False, mtu=1500):
    ip_class_by_addr_type = {socket.AF_INET: IP, socket.AF_INET6: IPv6}
    lcl = p.scapy_tun_sa = iptfs.SecurityAssociation(
        ESP,
        spi=p.scapy_tun_spi,
        crypt_algo=p.crypt_algo,
        crypt_key=p.crypt_key + p.crypt_salt,
        auth_algo=p.auth_algo,
        auth_key=p.auth_key,
        tunnel_header=ip_class_by_addr_type[p.addr_type](
            src=tun_if.local_addr, dst=tun_if.remote_addr
        ),
        nat_t_header=p.nat_header,
        esn_en=use_esn,
        mtu=mtu,
    )
    rem = p.linux_tun_sa = iptfs.SecurityAssociation(
        ESP,
        spi=p.linux_tun_spi,
        crypt_algo=p.crypt_algo,
        crypt_key=p.crypt_key + p.crypt_salt,
        auth_algo=p.auth_algo,
        auth_key=p.auth_key,
        tunnel_header=ip_class_by_addr_type[p.addr_type](
            dst=tun_if.local_addr, src=tun_if.remote_addr
        ),
        nat_t_header=p.nat_header,
        esn_en=use_esn,
        mtu=mtu,
    )
    return lcl, rem


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


def chunkit(lst, chunk):
    for i in range(0, len(lst), chunk):
        yield lst[i : i + chunk]


def run(params, tun_if, args):
    mtu = args.mtu

    lsa, rsa = config_tun_params(params, tun_if, mtu=mtu)
    inner_ip_overhead = len(IP() / ICMP(seq=1))

    psize = args.psize
    if args.pstep:
        if args.pmax:
            pmaxsize = args.pmax
        else:
            pmaxsize = mtu - inner_ip_overhead - lsa.get_ipsec_overhead()

        if args.count:
            pcount = args.count
        else:
            # Walk the the sizes twice (i.e., wrap once)
            # pcount = 2 * (pmaxsize - psize + 1) // args.pstep

            # Walk spread one time
            pcount = (pmaxsize - psize + 1 + args.pstep - 1) // args.pstep
            if args.wrap:
                pcount *= args.wrap
    else:
        pcount = args.count if args.count else 100
        pmaxsize = None

    logging.info(
        "GENERATING from %s to %s count %s step %s", psize, pmaxsize, pcount, args.pstep
    )
    opkts = gen_ippkts(
        tun_if.local_addr,
        args.ping,
        payload_size=psize,
        payload_spread=pmaxsize,
        inc=args.pstep,
        count=pcount,
    )
    maxsz = max([len(x) for x in opkts])
    logging.info("GENERATED %s inner packets max size %s", len(opkts), maxsz)
    encpkts = iptfs.gen_encrypt_pktstream_pkts(lsa, tun_if, mtu, opkts, dontfrag=True)
    encpkts = tun_if.prep_pkts(encpkts)

    for chunk in chunkit(encpkts, 10):
        # logging.info("SENDING gratiutous arp on %s", tun_if.name)
        # tun_if.send_gratuitous_arp()

        logging.info("SENDING %s ipsec/iptfs packets", len(chunk))

        rxs, txs, rxerr, txerr = get_intf_stats(args.iface)
        assert max(rxerr) == 0, f"rxerr not 0, is {max(rxerr)}"
        assert max(txerr) == 0, f"txerr not 0, is {max(txerr)}"

        pkts = srp(
            chunk,
            verbose=1,
            timeout=5,
            promisc=1,
            nofilter=1,
            iface=args.iface,
        )
        logging.info("srp returns %s", pkts)

        rawpkts = [x.answer for x in pkts[0]]
        ippkts = [x[IP] for x in rawpkts if x.haslayer(ESP)]
        logging.info("RECEIVED %s ipsec packets", len(ippkts))

        nrxs, ntxs, rxerr, txerr = get_intf_stats(args.iface)
        assert max(rxerr) == 0, f"rxerr not 0, is {max(rxerr)}"
        assert max(txerr) == 0, f"txerr not 0, is {max(txerr)}"
        logging.info("STATS for %s: RX %s TX %s", args.iface, nrxs - rxs, ntxs - txs)

        decpkts = []
        for ippkt in ippkts:
            decpkts.append(rsa.decrypt(ippkt))
        pkts = iptfs.decap_frag_stream(decpkts)
        logging.info("DECAP %s inner packets", len(pkts))
        # for pkt in pkts:
        #     print("inner ICMP seq: {} pkt: {}".format(pkt[ICMP].seq, pkt.summary()))
        #     # pkt.show()


def main(*args):
    ap = argparse.ArgumentParser(args)
    ap.add_argument("--count", type=int, help="number of packets to generate")
    ap.add_argument("--iface", default="eth1", help="interfaec to operate on")
    ap.add_argument("--local", default="10.0.1.3", help="interfaec address")
    ap.add_argument("--mtu", type=int, default=1500, help="size of tunnel packets")
    ap.add_argument("--remote", default="10.0.1.2", help="interfaec address")
    ap.add_argument("--ping", default="10.0.0.1", help="interfaec address")
    ap.add_argument("--pmax", type=int, help="max payload size for spread")
    ap.add_argument(
        "--psize", type=int, default=0, help="payload size (start size for spread)"
    )
    ap.add_argument("--pstep", type=int, help="amount to step for size spread")
    ap.add_argument("-v", "--verbose", action="store_true", help="be verbose")
    ap.add_argument(
        "--wrap",
        type=int,
        help="number of times to wrap around the spread -- ignored if count given",
    )
    args = ap.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level, format="%(asctime)s %(levelname)s: TESTER: %(name)s: %(message)s"
    )

    if args.count and args.wrap:
        logging.error("only one of --count or --wrap allowed")
        sys.exit(1)

    conf.iface = args.iface

    tun_if = Interface(args.iface, local_addr=args.local, remote_addr=args.remote)
    params = IPsecIPv4Params()
    params.remote_tun_if_host = tun_if.remote_addr

    # The IP may have been removed from the intf to keep the kernel out of things
    # So we need to do arp.
    print("STARTING")

    # t = AsyncSniffer(iface=args.iface, prn=lambda x: x.summary())
    # t.start()
    # # ... do stuff
    # pkts = t.stop(join=True)

    try:
        run(params, tun_if, args)
    except Exception as error:
        logging.error("Unexpected exception: %s", error)

    print("FINISH")


if __name__ == "__main__":
    main()
