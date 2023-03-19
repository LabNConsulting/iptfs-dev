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
# pylint: disable=wrong-import-position,protected-access
"Unit tests utilizign scapy"
import logging
import os
from functools import partial

import pytest
from common.config import _network_up, create_scapy_sa_pair, setup_policy_tun
from common.scapy import Interface, send_recv_pkts
from munet.testing.fixtures import _unet_impl, achdir
from scapy.config import conf
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6

# from munet.cli import async_cli

# All tests are coroutines
pytestmark = pytest.mark.asyncio

SRCDIR = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module")
async def unet(request, rundir_module, pytestconfig):  # pylint: disable=W0621
    sdir = os.path.dirname(os.path.realpath(request.fspath))
    async with achdir(sdir, "unet_unshare fixture"):
        async for x in _unet_impl(
            rundir_module, pytestconfig, unshare=True, top_level_pidns=False
        ):
            yield x


@pytest.fixture(scope="module", autouse=True)
async def network_up(unet):
    await _network_up(unet, ipv6=unet.ipv6_enable)

    #
    # Scapy settings
    #
    # Reload now that unet is in a new namespace
    conf.ifaces.reload()
    conf.route.resync()

    # Defaults to 64k which leads to lots of packet drops on sniffers
    conf.bufsize = 2**18

    # conf.iface = "net1"
    unet.host_if = Interface("net0", local_addr="10.0.0.1", remote_addr="10.0.0.2")
    unet.tun_if = Interface("net1", local_addr="10.0.1.3", remote_addr="10.0.1.2")
    if unet.ipv6_enable:
        unet.host_if6 = Interface("net0", local_addr="fc00::1", remote_addr="fc00::2")
        unet.tun_if6 = Interface(
            "net1", local_addr="fc00:0:0:1::3", remote_addr="fc00:0:0:1::2"
        )

    # Need to deal with ARP entry not going away on DUT since we won't answer as scapy
    r1 = unet.hosts["r1"]

    r1.conrepl.cmd_raises("ping -c1 10.0.0.1")
    r1dev = r1.net_intfs["net0"]
    r1.conrepl.cmd_nostatus(f"ip neigh change {unet.host_if.local_addr} dev {r1dev}")

    r1.conrepl.cmd_raises("ping -c1 10.0.1.3")
    r1dev = r1.net_intfs["net1"]
    r1.conrepl.cmd_nostatus(f"ip neigh change {unet.tun_if.local_addr} dev {r1dev}")

    unet.cmd_raises("ping -c1 10.0.1.2")

    # Remove IP from our scapy node
    unet.cmd_raises("ip addr del 10.0.0.1/24 dev net0")
    unet.cmd_raises("ip addr del 10.0.1.3/24 dev net1")


#                 192.168.0.0/24
#              +------ mgmt0 -------+
#              | .2                 | .254
#            +----+  10.0.1.0/24 +------+
#    +------ | r1 | --- net1 --- | unet | ... net2 ...
#    |    .2 +----+ .2        .3 +------+    10.0.2.0/24
#    |                               | .1
#    +----------- net0 --------------+


def getecn(pkt):
    return pkt[IP].tos & 0x3 if IP in pkt else pkt[IPv6].tc & 0x3


def getdscp(pkt):
    return (pkt[IP].tos if IP in pkt else pkt[IPv6].tc) >> 2


def setecn(pkt, val):
    if IP in pkt:
        pkt.tos = (pkt.tos & ~0x3) | (val & 0x3)
        pkt.chksum = None
    else:
        pkt.tc = (pkt.tc & ~0x3) | (val & 0x3)
    return pkt


def setdscp(pkt, val):
    val = (val & 0x3F) << 2
    if IP in pkt:
        pkt.tos = (pkt.tos & 0x3) | val
        pkt.chksum = None
    else:
        pkt.tc = (pkt.tc & 0x3) | val
    return pkt


@pytest.mark.parametrize("tun_ipv6", [False, True])
@pytest.mark.parametrize("ipv6", [False, True])
@pytest.mark.parametrize("noecn", ["", "noecn"])
@pytest.mark.parametrize("decap_dscp", ["", "decap-dscp"])
@pytest.mark.parametrize("dont_encap_dscp", ["dont-encap-dscp", ""])
async def test_ecn_encap(
    unet, astepf, ipv6, tun_ipv6, noecn, decap_dscp, dont_encap_dscp
):
    flags = f"{noecn} {decap_dscp}"
    flags += " extra-flag dont-encap-dscp" if dont_encap_dscp else ""
    await setup_policy_tun(
        unet,
        r1only=True,
        mode=MODE,
        iptfs_opts="",
        esp_flags=flags,
        ipv6=ipv6,
        tun_ipv6=tun_ipv6,
    )

    host_if = unet.host_if6 if ipv6 else unet.host_if
    tun_if = unet.tun_if6 if tun_ipv6 else unet.tun_if
    sa, _ = create_scapy_sa_pair(
        mode=MODE,
        addr1=tun_if.remote_addr,
        addr2=tun_if.local_addr,
        seq_num2=0,
        tun_ipv6=tun_ipv6,
    )
    if ipv6:
        _ippkt = IPv6(src="fc00::1", dst="fc00:0:0:2::4") / UDP()
    else:
        _ippkt = IP(src="10.0.0.1", dst="10.0.2.4") / UDP()
    # filtering the IPsec tunnel endpoint
    srp = partial(
        send_recv_pkts,
        rxfilter="dst host 10.0.1.3 or dst host fc00:0:0:1::3",
        delay=0.1,
    )

    await astepf("about to send ECN set IP packets")

    for ect in range(0, 4):
        ippkt = setecn(_ippkt, ect)
        ippkts = host_if.add_ether_encap([ippkt])
        pkts, opkts = srp(ippkts, "net0", sa, "net1")
        if noecn:
            assert 0 == getecn(opkts[0])
            assert ect == getecn(pkts[0])
        elif ect == 0x3:
            # RFC 3168 9.1.1 inner CE (3) -> outer ECT0 (2), else copy
            assert 3 == getecn(pkts[0])
            assert 2 == getecn(opkts[0])
        else:
            # RFC 3168 9.1.1 inner CE (3) -> outer ECT0 (2), else copy
            assert ect == getecn(opkts[0])
            assert ect == getecn(pkts[0])


MODE = "tunnel"


@pytest.mark.parametrize("tun_ipv6", [False, True])
@pytest.mark.parametrize("ipv6", [False, True])
@pytest.mark.parametrize("noecn", ["noecn", ""])
@pytest.mark.parametrize("decap_dscp", ["", "decap-dscp"])
@pytest.mark.parametrize("dont_encap_dscp", ["dont-encap-dscp", ""])
async def test_ecn_decap(
    unet, astepf, ipv6, tun_ipv6, noecn, decap_dscp, dont_encap_dscp
):
    flags = f"{noecn} {decap_dscp}"
    flags += " extra-flag dont-encap-dscp" if dont_encap_dscp else ""
    await setup_policy_tun(
        unet,
        r1only=True,
        mode=MODE,
        iptfs_opts="",
        esp_flags=flags,
        ipv6=ipv6,
        tun_ipv6=tun_ipv6,
    )

    tun_if = unet.tun_if6 if tun_ipv6 else unet.tun_if
    _, sa = create_scapy_sa_pair(
        mode=MODE,
        addr1=tun_if.remote_addr,
        addr2=tun_if.local_addr,
        seq_num2=0,
        tun_ipv6=tun_ipv6,
    )
    if ipv6:
        _ippkt = IPv6(dst="fc00::1", src="fc00:0:0:2::4") / UDP()
    else:
        _ippkt = IP(dst="10.0.0.1", src="10.0.2.4") / UDP()
    # filtering on the destination host
    srp = partial(
        send_recv_pkts, rxfilter="dst host 10.0.0.1 or dst host fc00::1", delay=0.1
    )

    await astepf("sending with no congestion on tunnel")

    #
    # No congestion encounter over tunnel
    #

    for ect in range(0, 4):
        ippkt = setecn(_ippkt, ect)
        epkts = [sa._encrypt_esp(x) for x in ippkt]
        setecn(epkts[0], 2 if ect == 3 else ect)
        epkts = tun_if.add_ether_encap(epkts)
        pkts, _ = srp(epkts, "net1", None, "net0")
        # inner maintained or copied
        assert ect == getecn(pkts[0])

    await astepf("sending with congestion on tunnel")
    #
    # Congestion encountere over tunnel
    #

    for ect in range(0, 4):
        ippkt = setecn(_ippkt, ect)
        # epkts = encrypt_pktstream_pkts(sa, [ippkt], pad=False)
        epkts = [sa._encrypt_esp(x) for x in ippkt]
        # RFC 3168 9.1.1 inner CE (3) -> outer ECT0 (2)
        # the 0 inner, 3 outer would be a bug on the path since the ingress
        # router should copy non-ECT(0) so then CE should not get set later.
        setecn(epkts[0], 3)
        epkts = tun_if.add_ether_encap(epkts)
        pkts, _ = srp(epkts, "net1", None, "net0")
        if noecn:
            # inner maintained
            assert getecn(ippkt) == getecn(pkts[0])
        else:
            if ect in [1, 2]:
                # inner enabled, outer CE copied
                assert 3 == getecn(pkts[0])
            else:
                # inner disabled or CE, outer ignored
                assert ect == getecn(pkts[0])


@pytest.mark.parametrize("tun_ipv6", [False, True])
@pytest.mark.parametrize("ipv6", [False, True])
@pytest.mark.parametrize("ecn", ["noecn", ""])
@pytest.mark.parametrize("dont_encap_dscp", ["dont-encap-dscp", ""])
async def test_dscp_encap(unet, astepf, ipv6, tun_ipv6, ecn, dont_encap_dscp):
    flags = f"{ecn}"
    flags += " extra-flag dont-encap-dscp" if dont_encap_dscp else ""
    await setup_policy_tun(
        unet,
        r1only=True,
        mode=MODE,
        iptfs_opts="",
        esp_flags=flags,
        ipv6=ipv6,
        tun_ipv6=tun_ipv6,
    )

    host_if = unet.host_if6 if ipv6 else unet.host_if
    tun_if = unet.tun_if6 if tun_ipv6 else unet.tun_if
    sa, _ = create_scapy_sa_pair(
        mode=MODE,
        addr1=tun_if.remote_addr,
        addr2=tun_if.local_addr,
        seq_num2=0,
        tun_ipv6=tun_ipv6,
    )
    if ipv6:
        _ippkt = IPv6(src="fc00::1", dst="fc00:0:0:2::4") / UDP()
    else:
        _ippkt = IP(src="10.0.0.1", dst="10.0.2.4") / UDP()
    # filtering the IPsec tunnel endpoint
    srp = partial(
        send_recv_pkts,
        rxfilter="dst host 10.0.1.3 or dst host fc00:0:0:1::3",
        delay=0.1,
    )

    await astepf("about to send DSCP set inner packets")

    for dscp in (0x1, 0x15, 0x2A, 0x3F):
        ippkt = setdscp(_ippkt, dscp)
        ippkts = host_if.add_ether_encap([ippkt])
        pkts, opkts = srp(ippkts, "net0", sa, "net1")
        print("DSCP: ", getdscp(ippkts[0]), getdscp(opkts[0]), getdscp(pkts[0]))
        if dont_encap_dscp:
            # dscp should not be copied
            assert 0 == getdscp(opkts[0])
        else:
            # dscp should be copied
            assert dscp == getdscp(opkts[0])
        # the inner packet should not be changed
        assert dscp == getdscp(pkts[0])


@pytest.mark.parametrize("tun_ipv6", [False, True])
@pytest.mark.parametrize("ipv6", [False, True])
@pytest.mark.parametrize("decap_dscp", ["", "decap-dscp"])
async def test_dscp_decap(unet, astepf, ipv6, tun_ipv6, decap_dscp):
    flags = f"{decap_dscp}"
    await setup_policy_tun(
        unet,
        r1only=True,
        mode=MODE,
        iptfs_opts="",
        esp_flags=flags,
        ipv6=ipv6,
        tun_ipv6=tun_ipv6,
    )

    tun_if = unet.tun_if6 if tun_ipv6 else unet.tun_if
    _, sa = create_scapy_sa_pair(
        mode=MODE,
        addr1=tun_if.remote_addr,
        addr2=tun_if.local_addr,
        seq_num2=0,
        tun_ipv6=tun_ipv6,
    )
    if ipv6:
        _ippkt = IPv6(dst="fc00::1", src="fc00:0:0:2::4") / UDP()
    else:
        _ippkt = IP(dst="10.0.0.1", src="10.0.2.4") / UDP()
    srp = partial(
        send_recv_pkts, rxfilter="dst host 10.0.0.1 or dst host fc00::1", delay=0.1
    )

    await astepf("about to send DSCP IPsec packets")

    for odscp in (0, 0x3F):
        for idscp in (0, 0x3F):
            ippkt = setdscp(_ippkt, idscp)
            epkts = [sa._encrypt_esp(x) for x in ippkt]
            setdscp(epkts[0], odscp)
            epkts = tun_if.add_ether_encap(epkts)
            pkts, _ = srp(epkts, "net1", None, "net0")
            print("odscp 0x%x idscp 0x%x" % (odscp, idscp))
            if decap_dscp:
                assert odscp == getdscp(pkts[0])
            else:
                assert idscp == getdscp(pkts[0])
