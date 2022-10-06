#!/usr/bin/env python
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
"External command to generate and receipve IPTFS packets."

import argparse
import logging
import sys

from common import iptfs
from common.config import create_scapy_sa_pair
from common.scapy import Interface, gen_ippkts
from common.testutil import chunkit, get_intf_stats
from scapy.config import conf
from scapy.layers.inet import ICMP, IP
from scapy.layers.ipsec import ESP
from scapy.sendrecv import srp

# 3: eth1@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
#         qdisc noqueue state UP mode DEFAULT group default qlen 1000
#     link/ether 6a:a1:3f:28:7b:fb brd ff:ff:ff:ff:ff:ff link-netnsid 0
#     RX:  bytes packets errors dropped  missed   mcast
#        1015906     895      0       0       0       0
#     TX:  bytes packets errors dropped carrier collsns
#        1420434     943      0       0       0       0


def run(tun_if, args):
    mtu = args.mtu

    osa, sa = create_scapy_sa_pair(
        mtu=mtu, addr1=tun_if.remote_addr, addr2=tun_if.local_addr
    )
    inner_ip_overhead = len(IP() / ICMP(seq=1))

    psize = max(args.psize, inner_ip_overhead)
    if args.pstep:
        if args.pmax:
            pmaxsize = max(args.pmax, args.psize)
        else:
            pmaxsize = mtu - inner_ip_overhead - sa.get_ipsec_overhead()

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
        payload_size=psize - inner_ip_overhead,
        payload_spread=pmaxsize,
        inc=args.pstep,
        count=pcount,
    )
    maxsz = max(len(x) for x in opkts)
    logging.info("GENERATED %s inner packets max size %s", len(opkts), maxsz)
    encpkts = iptfs.gen_encrypt_pktstream_pkts(sa, mtu, opkts, dontfrag=args.df)
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
        logging.info("SRP RETURNS %s", pkts)

        rawpkts = [x.answer for x in pkts[0]]
        ippkts = [x[IP] for x in rawpkts if x.haslayer(ESP)]
        nippkts = len(ippkts)
        logging.info("RECEIVED %s ipsec packets", nippkts)

        nrxs, ntxs, rxerr, txerr = get_intf_stats(args.iface)
        assert max(rxerr) == 0, f"rxerr not 0, is {max(rxerr)}"
        assert max(txerr) == 0, f"txerr not 0, is {max(txerr)}"
        logging.info("STATS for %s: RX %s TX %s", args.iface, nrxs - rxs, ntxs - txs)

        try:
            decpkts = []
            for ippkt in ippkts:
                decpkts.append(osa.decrypt(ippkt))
            pkts = iptfs.decap_frag_stream(decpkts)
            logging.info(
                "DECAP %s inner packets from %s ipsec packets", len(pkts), nippkts
            )
        except Exception as error:
            logging.info(
                "Exception decapping received ESP packets: %s", error, exc_info=True
            )
            return 1

        # for pkt in pkts:
        #     print("inner ICMP seq: {} pkt: {}".format(pkt[ICMP].seq, pkt.summary()))
        #     # pkt.show()
    return 0


def main(*args):
    ap = argparse.ArgumentParser(args)
    ap.add_argument("--count", type=int, help="number of packets to generate")
    ap.add_argument("--df", action="store_true", help="dont fragment")
    ap.add_argument("--iface", default="eth1", help="interfaec to operate on")
    ap.add_argument("--local", default="10.0.1.3", help="interfaec address")
    ap.add_argument("--mtu", type=int, default=1500, help="size of tunnel packets")
    ap.add_argument("--remote", default="10.0.1.2", help="interfaec address")
    ap.add_argument("--ping", default="10.0.0.1", help="interfaec address")
    ap.add_argument("--pmax", type=int, help="max inner pkt size for spread")
    ap.add_argument(
        "--psize", type=int, default=0, help="inner pkt size (start size for spread)"
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
        sys.exit(2)

    conf.iface = args.iface
    tun_if = Interface(args.iface, local_addr=args.local, remote_addr=args.remote)

    # The IP may have been removed from the intf to keep the kernel out of things
    # So we need to do arp.
    logging.info("STARTING")

    # t = AsyncSniffer(iface=args.iface, prn=lambda x: x.summary())
    # t.start()
    # # ... do stuff
    # pkts = t.stop(join=True)

    try:
        ec = run(tun_if, args)
    except Exception as error:
        logging.error("Unexpected exception: %s", error, exc_info=True)
        ec = 255

    logging.info("FINISH")
    sys.exit(ec)


if __name__ == "__main__":
    main()
