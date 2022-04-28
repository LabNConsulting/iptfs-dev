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
import binascii
import logging
import os
import re
import socket
import subprocess
import time
from datetime import datetime, timedelta

import pytest
from munet.base import comm_error
from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.config import conf
from scapy.layers.inet import ICMP, IP
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import ESP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.sendrecv import sendp, srp

import iptfs

# from munet.cli import async_cli

# All tests are coroutines
pytestmark = pytest.mark.asyncio

SRCDIR = os.path.dirname(os.path.abspath(__file__))


async def console(unet, rtr):
    # cmd = ["socat", "-,rawer,echo=0,icanon=0", "unix-connect:/tmp/qemu-sock/console"]
    cmd = ["socat", "-", "unix-connect:/tmp/qemu-sock/console"]
    # cmd = [
    #     "socat",
    #     "/dev/stdin,rawer,echo=0,icanon=0",
    #     "unix-connect:/tmp/qemu-sock/console",
    # ]
    rtr = unet.hosts[rtr] if isinstance(rtr, str) else rtr
    time.sleep(1)
    repl = await rtr.console(cmd, user="root", use_pty=False, trace=True)
    repl.cmd_status("set +o emacs")
    return repl


@pytest.fixture(scope="module", name="r1repl")
async def r1repl_(unet):
    return await console(unet, unet.hosts["r1"])


@pytest.fixture(scope="module", autouse=True)
async def network_up(unet, r1repl):
    h1 = unet.hosts["h1"]
    r1 = unet.hosts["r1"]

    unet.cmd_raises("sysctl -w net.ipv6.conf.all.autoconf=0")
    unet.cmd_raises("sysctl -w net.ipv6.conf.all.disable_ipv6=1")

    # Need to configure inside qemu now
    r1repl.cmd_raises("sysctl -w net.ipv6.conf.all.autoconf=0")
    r1repl.cmd_raises("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    r1repl.cmd_raises("sysctl -w net.ipv4.ip_forward=1")
    r1repl.cmd_raises("ip link set lo up")
    for i in range(0, len(r1.intf_addrs)):
        r1repl.cmd_raises(f"ip link set eth{i} up")
        r1repl.cmd_raises(f"ip addr add {r1.intf_addrs[f'eth{i}']} dev eth{i}")

    h1.cmd_raises("ip route add 10.0.2.0/24 via 10.0.0.2")
    h1.cmd_raises("ip route add 10.0.1.0/24 via 10.0.0.2")

    r1repl.cmd_raises("ip route add 10.0.2.0/24 via 10.0.1.3")

    unet.cmd_raises("ip addr del 10.0.1.3/24 dev net1")


#                             192.168.0.0/24
#   --+-------------------+------ mgmt0 ------+-------------------+---
#     | .1                | .2                | .3                | .4
#   +----+              +----+              +----+              +----+
#   | h1 | --- net0 --- | r1 | --- net1 --- | r2 | --- net2 --- | r1 |
#   +----+ .1        .2 +----+ .2        .3 +----+ .3        .4 +----+
#          10.0.0.0/24         10.0.1.0/24         10.0.2.0/24


async def test_net_up(unet, r1repl):
    h1 = unet.hosts["h1"]

    # h1 pings r1 (qemu side)
    logging.debug(h1.cmd_raises("ping -w1 -i.2 -c1 10.0.0.2"))
    # h1 pings r1 (namespace side)
    logging.debug(h1.cmd_raises("ping -w1 -i.2 -c1 10.0.0.202"))
    # h1 pings r1 (other side)
    logging.debug(h1.cmd_raises("ping -w1 -i.2 -c1 10.0.1.2"))

    # r1 (qemu side) pings h1
    logging.debug(r1repl.cmd_raises("ping -w1 -i.2 -c1 10.0.0.1"))
    # r1 (qemu side) pings r1 (namespace side)
    logging.debug(r1repl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.202"))


MODE = "mode iptfs"
USE_GCM = True
USE_NULLNULL = False


async def setup_policy_tun(unet, r1repl):
    r1 = unet.hosts["r1"]
    s1 = unet.switches["net1"]

    rspi = 0xAA
    lspi = 0xBB
    sa_auth = "auth sha256 0x0123456789ABCDEF0123456789ABCDEF"
    sa_enc = "enc aes 0xFEDCBA9876543210FEDCBA9876543210"
    # sa_auth = "auth sha256 0x0123456789ABCDEF0123456789ABCDEF"
    # sa_enc = 'enc cipher_null ""'

    if not USE_GCM:
        if USE_NULLNULL:
            rspi = 0xAAAA
            lspi = 0xBBBB
            sa_auth = 'auth digest_null ""'
            # sa_auth = "auth sha256 0x0123456789ABCDEF0123456789ABCDEF"
            # sa_auth = 'auth digest_null ""'
            sa_enc = 'enc cipher_null ""'
        else:
            rspi = 0xAAAA
            lspi = 0xBBBB
            sa_auth = "auth sha1 0x4339314b55523947594d6d3547666b45764e6a58"
            # sa_auth = "auth sha256 0x0123456789ABCDEF0123456789ABCDEF"
            # sa_auth = 'auth digest_null ""'
            sa_enc = 'enc cipher_null ""'
    else:
        rspi = 0xAA
        lspi = 0xBB
        sa_auth = ""
        sa_enc = (
            'aead "rfc4106(gcm(aes))" '
            "0x4a506a794f574265564551694d6537681A2B1A2B "
            "128"
            # "0x4a506a794f574265564551694d6537684a506a794f574265564551694d6537681A2B1A2B "
            # "256"
        )

    r1ipp = r1.net_addr("net1")
    r2ipp = s1.ip_interface
    r1ip = r1ipp.ip
    r1ipp = r1ipp.network
    r2ip = r2ipp.ip
    r2ipp = r2ipp.network

    for r, repl in [(r1, r1repl)]:
        #
        # SAs
        #
        repl.cmd_raises(
            f"ip xfrm state add src {r1ip} dst {r2ip} proto esp "
            f"spi {rspi} {MODE} {sa_auth} {sa_enc} "
            f"reqid 0x10"
        )
        repl.cmd_raises(
            f"ip xfrm state add src {r2ip} dst {r1ip} proto esp "
            f"spi {lspi} {MODE} {sa_auth} {sa_enc} "
            f"reqid 0x11"
        )

        #
        # Policy
        #
        for x1ipp, x2ipp in [
            ("10.0.0.0/24", "10.0.1.0/24"),  # host to router
            ("10.0.1.0/24", "10.0.1.0/24"),  # router to router
            ("10.0.1.0/24", "10.0.2.0/24"),  # host to router
            ("10.0.0.0/24", "10.0.2.0/24"),  # host to host
        ]:
            for direction in ["dir out"] if r == r1 else ["dir fwd", "dir in"]:
                repl.cmd_raises(
                    f"ip xfrm policy add src {x1ipp} dst {x2ipp} {direction} "
                    f"tmpl src {r1ip} dst {r2ip} proto esp {MODE} "
                    f"reqid 0x10",  # " spi {rspi} "
                )
            for direction in ["dir out"] if r != r1 else ["dir fwd", "dir in"]:
                repl.cmd_raises(
                    f"ip xfrm policy add src {x2ipp} dst {x1ipp} {direction} "
                    f"tmpl src {r2ip} dst {r1ip} proto esp {MODE} "
                    f"reqid 0x11",  # " spi {lspi} "
                )


async def setup_routed_tun(unet, r1repl):
    r1 = unet.hosts["r1"]
    s1 = unet.switches["net1"]

    reqid_1to2 = 8
    reqid_2to1 = 9
    spi_1to2 = 0xAAAA
    spi_2to1 = 0xBBBB
    # sa_aut 'auth digest_null ""'
    sa_auth = "auth sha256 0x0123456789ABCDEF0123456789ABCDEF"
    sa_enc = 'enc cipher_null ""'

    r1ipp = r1.net_addr("net1")
    r2ipp = s1.ip_interface
    r1ip = r1ipp.ip
    r1ipp = r1ipp.network
    r2ip = r2ipp.ip
    r2ipp = r2ipp.network

    # Get rid of non-ipsec routes
    r1repl.cmd_raises("ip route del 10.0.2.0/24 via 10.0.1.3")
    # r2repl.cmd_raises("ip route del 10.0.0.0/24 via 10.0.1.2")

    for r, repl in [(r1, r1repl)]:
        #
        # SAs
        #
        if r == r1:
            oreqid, ireqid = reqid_1to2, reqid_2to1
            ospi, ispi = spi_1to2, spi_2to1
            lip = r1ip
            rip = r2ip
        else:
            oreqid, ireqid = reqid_2to1, reqid_1to2
            ospi, ispi = spi_2to1, spi_1to2
            lip = r2ip
            rip = r1ip

        repl.cmd_raises(
            f"ip xfrm state add src {r1ip} dst {r2ip} proto esp "
            f"spi {spi_1to2} {MODE} {sa_auth} {sa_enc} "
            f"if_id 55 reqid {reqid_1to2}"
        )
        repl.cmd_raises(
            f"ip xfrm state add src {r2ip} dst {r1ip} proto esp "
            f"spi {spi_2to1} {MODE} {sa_auth} {sa_enc} "
            f"if_id 55 reqid {reqid_2to1}"
        )

        repl.cmd_raises(
            "ip link add ipsec0 type xfrm dev {r.net_intfs['net1']} if_id 55"
        )
        repl.cmd_raises("sysctl -w net.ipv4.conf.ipsec0.disable_policy=1")
        repl.cmd_raises("ip link set ipsec0 up")

        #
        # Policy
        #
        direction = "dir out"
        xdef = "0.0.0.0/0"

        # No interface (non-routed) policy for the tunnel
        # repl.cmd_raises(
        #     f"ip xfrm policy add src {xdef} dst {rip} {direction}"
        #     f" tmpl src {lip} dst {rip} proto esp spi {ospi} {MODE} reqid 20"
        # )

        # Interface based policy for everything else
        repl.cmd_raises(
            f"ip xfrm policy add if_id 55 src {xdef} dst {xdef} {direction}"
            f" tmpl src {lip} dst {rip} proto esp spi {ospi} {MODE} reqid {oreqid}"
        )

        for direction in ["dir fwd", "dir in"]:
            repl.cmd_raises(
                f"ip xfrm policy add if_id 55 src {xdef} dst {xdef} {direction} "
                f"tmpl src {rip} dst {lip} proto esp spi {ispi} {MODE} reqid {ireqid}"
            )

    # Add ipsec0 based routes
    r1repl.cmd_raises("ip route add 10.0.2.0/24 dev ipsec0 src 10.0.1.2")
    # r2repl.cmd_raises("ip route add 10.0.0.0/24 dev ipsec0 src 10.0.1.3")


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
    while datetime.now() < retry_until:
        # line = p.stdout.readline()
        line = myreadline(p.stdout)
        if not line:
            assert None, f"Timeout waiting for '{regex}'"
        line = line.rstrip()
        if line:
            logging.info("GOT LINE: '%s'", line)
        m = re.search(regex, line)
        if m:
            return m
    assert None, f"Failed to get output withint {timeout}s"


USE_GCM = True


class Interface:
    def __init__(self, name, local_addr, remote_addr):
        self.local_mac = get_if_hwaddr(name)
        self.local_addr = local_addr
        self.remote_addr = remote_addr

        # result = sr1(ARP(op=ARP.who_has, psrc='192.168.1.2', pdst='192.168.1.1'))
        pkt = Ether(src=self.local_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            psrc=local_addr, pdst=remote_addr
        )
        ans, _ = srp(pkt, iface=name)
        self.remote_mac = ans[0][1][ARP].hwsrc
        logging.debug("Interface: %s remote mac is %s", remote_addr, self.remote_mac)

    def prep_pkts(self, pkts):
        npkts = []
        for pkt in pkts:
            npkts.append(Ether(src=self.local_mac, dst=self.remote_mac) / pkt)
        return npkts


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


def config_tun_params(p, tun_if, use_esn=False, mtu=1400):
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
        emptylen = len(IP(src=src, dst=dst) / ICMP(seq=1))
        pkts = []
        start = payload_size
        end = payload_spread
        psize = start
        for i in range(count):
            pkts.append(IP(src=src, dst=dst) / ICMP(seq=i + 1) / Raw("X" * (psize)))
            psize += inc
            if psize + emptylen >= end:
                # wrap around
                psize = start + end - (psize + emptylen)
        return pkts


def run(params, tun_if):

    lsa, rsa = config_tun_params(params, tun_if)

    pinc = 23
    payload = 1400
    psize = 54
    pmaxsize = payload - lsa.get_ipsec_overhead() - 4
    pcount = 2 * (pmaxsize - psize + 1) // pinc
    opkts = gen_ippkts(
        tun_if.local_addr,
        "10.0.0.1",
        payload_size=psize,
        payload_spread=pmaxsize,
        inc=pinc,
        count=pcount,
    )
    logging.info("GENERATED %s inner packets max size %s", len(opkts), len(opkts[-1]))
    encpkts = iptfs.gen_encrypt_pktstream_pkts(
        lsa, tun_if, payload, opkts, dontfrag=True
    )
    encpkts = tun_if.prep_pkts(encpkts)
    logging.info("SENDING %s ipsec/iptfs packets", len(encpkts))
    pkts = srp(
        encpkts,
        verbose=1,
        timeout=15,
        promisc=1,
        nofilter=1,
        iface="net1",
    )
    rawpkts = [x.answer for x in pkts[0]]
    ippkts = [x[IP] for x in rawpkts if x.haslayer(ESP)]
    logging.info("RECEIVED %s ipsec packets", len(ippkts))
    decpkts = []
    for ippkt in ippkts:
        decpkts.append(rsa.decrypt(ippkt))
    pkts = iptfs.decap_frag_stream(decpkts)
    logging.info("DECAP %s inner packets", len(pkts))
    # for pkt in pkts:
    #     print("inner ICMP seq: {} pkt: {}".format(pkt[ICMP].seq, pkt.summary()))
    #     # pkt.show()


async def test_scapy_script(unet, r1repl, astepf):
    await setup_policy_tun(unet, r1repl)

    conf.iface = "net1"

    tun_if = Interface("net1", local_addr="10.0.1.3", remote_addr="10.0.1.2")
    params = IPsecIPv4Params()
    params.remote_tun_if_host = tun_if.remote_addr

    run(params, tun_if)
