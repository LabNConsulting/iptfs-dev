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
import logging
import os
import re
import subprocess
import time
from datetime import datetime, timedelta

import pytest
from common import iptfs
from common.config import create_scapy_sa_pair, setup_policy_tun, toggle_ipv6
from common.scapy import Interface, gen_ippkts
from common.testutil import Timeout, chunkit, get_intf_stats
from munet.base import comm_error
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
    regex = re.compile(regex)
    while datetime.now() < retry_until:
        line = myreadline(p.stdout)
        if not line:
            assert None, f"EOF waiting for '{regex}'"
        line = line.rstrip()
        if line:
            logging.info("GOT LINE: '%s'", line)
        m = regex.search(line)
        if m:
            return m
    assert None, f"Failed to get output withint {timeout}s"


def send_recv_iptfs_pkts(osa, encpkts, iface, chunksize=30, faster=False):

    rxs, txs, rxerr, txerr = get_intf_stats(iface)
    assert max(rxerr) == 0, f"rxerr not 0, is {max(rxerr)}"
    assert max(txerr) == 0, f"txerr not 0, is {max(txerr)}"

    def get_esp_pkts(pkts):
        rawpkts = (x.answer for x in pkts)
        pkts = [x[IP] for x in rawpkts if x.haslayer(ESP)]
        logging.info("RECEIVED %s ipsec packets", len(pkts))
        return pkts

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
    #     logging.info("sending chunk %s with %s ipsec/iptfs packets", nchunk, len(chunk))

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

    # # If we arrive here w/o exceptions (from timeout or break) let's take another second
    # # to see if we have anymore packets coming.
    # timeout = 1
    # logging.info("Waiting %ss for final packets", timeout)
    # pkts = sniff(timeout=timeout, promisc=1, nofilter=1, iface=iface)
    # logging.info("Final sniff returns %s", pkts)

    # XXX improve this, sleep 2 seconds for things to flush
    time.sleep(2)

    net0results = net0sniffer.stop()
    # net0results = []
    net1results = net1sniffer.stop()

    # _esppkts = get_esp_pkts(pkts)
    pkts = [x[IP] for x in net1results if x.haslayer(ESP)]
    # XXX should use iface ip local addr
    _esppkts = [x for x in pkts if x.src != "10.0.1.3"]
    logging.info("RECEIVED %s ipsec packets", len(_esppkts))

    outer_pkts.extend(_esppkts)
    if _esppkts:
        _decpkts = process_esp_pkts(_esppkts, -1)
        decpkts.extend(_decpkts)

    _pkts = iptfs.decap_frag_stream(decpkts)

    # Greb echo replies.
    inner_pkts = [x for x in _pkts if x.haslayer(ICMP) and x[ICMP].type == 0]
    other_inner_pkts = [x for x in _pkts if not x.haslayer(ICMP) or x[ICMP].type != 0]

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


async def gen_pkt_test(
    unet,
    astepf,
    ping="10.0.0.1",
    mtu=1500,
    df=False,
    psize=0,
    pstep=0,
    pmax=0,
    count=0,
    wrap=False,
    iface="net1",
    nofail=False,
):
    osa, sa = create_scapy_sa_pair(
        mtu=mtu, addr1=unet.tun_if.remote_addr, addr2=unet.tun_if.local_addr
    )
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

    encpkts = iptfs.gen_encrypt_pktstream_pkts(sa, mtu, opkts, dontfrag=df)
    encpkts = unet.tun_if.prep_pkts(encpkts)

    r1 = unet.hosts["r1"]
    output = r1.conrepl.cmd_nostatus("ip -s link show eth2")
    logging.info("r1 eth2:\n%s", output)
    output = r1.conrepl.cmd_nostatus("ip -s link show eth1")
    logging.info("r1 eth1:\n%s", output)

    is_kvm = r1.is_kvm if hasattr(r1, "is_kvm") else False
    pkts, _, net0pkts = send_recv_iptfs_pkts(osa, encpkts, iface, faster=is_kvm)

    output = r1.conrepl.cmd_nostatus("ip -s link show eth2")
    logging.info("r1 eth2:\n%s", output)
    output = r1.conrepl.cmd_nostatus("ip -s link show eth1")
    logging.info("r1 eth1:\n%s", output)

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
        _ = _wait_output(p, "STARTING")

        m = _wait_output(p, r"DECAP (\d+) inner packets")
        ndecap = int(m.group(1))
        assert (
            ndecap == expected
        ), f"Wrong number ({ndecap}, expected {expected}) return IP packets"

        _ = _wait_output(p, "FINISH")

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
    await gen_pkt_test(unet, astepf, psize=0, pstep=1)
    # await gen_pkt_test(unet, astepf, psize=1400, pmax=1438, pstep=1)


async def test_spread_recv_frag_toobig_reply(unet, astepf):
    await setup_policy_tun(unet, r1only=True, iptfs_opts="dont-frag")
    await astepf("Prior to gen_pkt_test")
    npkts, nopkts, nnet0pkts = await gen_pkt_test(
        unet, astepf, psize=1442, pmax=1443, pstep=1, nofail=True
    )
    # one echo reply is too big
    assert npkts == 1 and nnet0pkts == 2 and nopkts == 2


async def test_recv_frag(unet, astepf):
    await setup_policy_tun(unet, r1only=True, iptfs_opts="dont-frag")
    await astepf("Prior to gen_pkt_test")
    await gen_pkt_test(unet, astepf, psize=411, mtu=500, pstep=1, count=2)


async def test_small_pkt_agg(unet, astepf):
    await setup_policy_tun(unet, r1only=True, iptfs_opts="dont-frag")
    await astepf("Prior to gen_pkt_test")
    await gen_pkt_test(unet, astepf, count=80)
