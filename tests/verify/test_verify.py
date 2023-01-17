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
# import asyncio
import logging
import os
import subprocess

import pytest
from common.config import setup_policy_tun, toggle_ipv6
from common.tests import _test_net_up

# All tests are coroutines
pytestmark = pytest.mark.asyncio

SRCDIR = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module", autouse=True)
async def network_up(unet):
    h1 = unet.hosts["h1"]
    h2 = unet.hosts["h2"]
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]
    r1repl = r1.conrepl

    h1.cmd_raises("ip link set eth1 mtu 9000")
    r1.cmd_raises("ip link set eth1 mtu 9000")
    r1.conrepl.cmd_raises("ip link set eth1 mtu 9000")

    await toggle_ipv6(unet, enable=False)

    # for i in range(0, 3):
    #     unet.cmd_raises(f"sysctl -w net.ipv6.conf.net{i}.autoconf=0")
    #     unet.cmd_raises(f"sysctl -w net.ipv6.conf.net{i}.disable_ipv6=1")

    # #
    # # R1 - Linux
    # #
    # r1repl.cmd_raises("sysctl -w net.ipv4.ip_forward=1")
    # r1repl.cmd_raises("ip link set lo up")

    # for i in range(0, 3):
    #     r1repl.cmd_raises(f"sysctl -w net.ipv6.conf.eth{i}.autoconf=0")
    #     r1repl.cmd_raises(f"sysctl -w net.ipv6.conf.eth{i}.disable_ipv6=1")
    #     # r1repl.cmd_raises(f"ip addr flush dev eth{i}")
    #     r1repl.cmd_raises(f"ip link set eth{i} up")
    #     r1repl.cmd_raises(f"ip addr add {r1.intf_addrs[f'eth{i}']} dev eth{i}")

    r1repl.cmd_raises("ip route add 10.0.2.0/24 via 10.0.1.3")

    #
    # R2 - VPP
    #
    for i in range(0, 3):
        vppctl_raises(r2, f"vppctl set int state UnknownEthernet{i} up")
        vppctl_raises(
            r2,
            f"vppctl set int ip address UnknownEthernet{i} {r2.intf_addrs[f'eth{i}']}",
        )
    vppctl_raises(r2, "vppctl create loopback interface", "loop0")
    vppctl_raises(r2, "vppctl set int state loop0 up")

    # Need to populate ARP in VPP or first pings get dropped
    r2.cmd_raises("vppctl ping 10.0.1.2 repeat 1")
    r2.cmd_raises("vppctl ping 10.0.2.4 repeat 1")

    #
    # Hosts
    #
    h1.cmd_raises("ip route add 10.0.2.0/24 via 10.0.0.2")
    h1.cmd_raises("ip route add 10.0.1.0/24 via 10.0.0.2")

    h2.cmd_raises("ip route add 10.0.1.0/24 via 10.0.2.3")
    h2.cmd_raises("ip route add 10.0.0.0/24 via 10.0.2.3")


#                             192.168.0.0/24
#   --+-------------------+------ mgmt0 ------+-------------------+---
#     | .1                | .2                | .3                | .4
#   +----+              +----+              +----+              +----+
#   | h1 | --- net0 --- | r1 | --- net1 --- | r2 | --- net2 --- | r1 |
#   +----+ .1        .2 +----+ .2        .3 +----+ .3        .4 +----+
#          10.0.0.0/24         10.0.1.0/24         10.0.2.0/24


async def test_net_up(unet):
    r2 = unet.hosts["r2"]

    r2.cmd_raises("vppctl ip route add 10.0.0.0/24 via 10.0.1.2")

    await _test_net_up(unet)

    r2.cmd_raises("vppctl ip route del 10.0.0.0/24 via 10.0.1.2")


def vppctl_raises(r, cmd, ok_output=""):
    s, o, e = r.cmd_status(cmd)
    o = o.strip()
    e = e.strip()
    if s or o or e:
        # see fi this output is expected
        if not s and not e and o.strip() == ok_output.strip():
            return
        if s == 256:
            logging.warning("%s: XXX HUP for cmd: %s", r, cmd)
            return
        if not s:
            logging.warning("%s: XXX Unexpected output for cmd: %s", r, cmd)
            s = -1
        else:
            logging.warning("%s: XXX Bad status %s for cmd: %s", r, s, cmd)
        error = subprocess.CalledProcessError(s, cmd)
        error.stdout = o
        error.stderr = e
        raise error


async def setup_vpp_ipsec(
    unet, use_tfs=True, use_gcm=True, use_nullnull=False, enc_null=False
):
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]

    reqid_1to2 = 0x10
    reqid_2to1 = 0x11

    if not use_gcm:
        if use_nullnull:
            spi_1to2 = f"{0xAAAAAA}"
            spi_2to1 = f"{0xBBBBBB}"
            sa_auth = "integ-alg none "
            sa_enc = "crypto-alg none"
        else:
            # "integ-key 4339314b55523947594d6d3547666b45764e6a58 integ-alg sha1-96 "
            # sa_auth = ("integ-key 0123456789ABCDEF0123456789ABCDEF integ-alg sha-256-128 ")
            sa_auth = (
                "integ-key 0123456789ABCDEF0123456789ABCDEF01234567 integ-alg sha1-96 "
            )
            # sa_auth = "integ-key 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF integ-alg sha-256-128 "
            if enc_null:
                spi_1to2 = f"{0xAAAA}"
                spi_2to1 = f"{0xBBBB}"
                sa_enc = "crypto-alg none"
            else:
                spi_1to2 = f"{0xAA}"
                spi_2to1 = f"{0xBB}"
                sa_enc = (
                    "crypto-alg aes-cbc-128 "
                    "crypto-key FEDCBA9876543210FEDCBA9876543210 "
                )
    else:
        spi_1to2 = f"{0xAAA}"
        spi_2to1 = f"{0xBBB}"
        sa_auth = ""
        sa_enc = (
            "crypto-key 4a506a794f574265564551694d653768 "
            "crypto-alg aes-gcm-128 salt 0x1A2B1A2B "
        )
        # sa_enc = (
        #     "crypto-key 4a506a794f574265564551694d653768"
        #     "4a506a794f574265564551694d653768 "
        #     "crypto-alg aes-gcm-256 salt 0x1A2B1A2B "
        # )
    if use_tfs:
        iptfs_common = " tfs iptfs-nocc iptfs-mode encap-only"
        # have to specify a bitrate even though it's not used
        out_iptfs_opts = (
            iptfs_common
            + f" iptfs-inbound-sa-id {reqid_1to2} iptfs-packet-size 1400 iptfs-bitrate 1M"
        )
        in_iptfs_opts = iptfs_common
    else:
        out_iptfs_opts = ""
        in_iptfs_opts = ""

    # XXX DPDK backend 1 ONLY works for GCM
    vppctl_raises(r2, "vppctl ipsec select backend esp 0")
    vppctl_raises(r2, "vppctl ipsec itf create instance 0", "ipsec0")
    vppctl_raises(
        r2,
        f"vppctl ipsec sa add {reqid_1to2} spi {spi_1to2} esp {sa_enc} {sa_auth} "
        f"tunnel-src {r1.intf_addrs['eth2'].ip} tunnel-dst {r2.intf_addrs['eth2'].ip} "
        "inbound" + in_iptfs_opts
        # " use-esn use-anti-replay inbound",
    )
    vppctl_raises(
        r2,
        f"vppctl ipsec sa add {reqid_2to1} spi {spi_2to1} esp {sa_enc} {sa_auth} "
        f"tunnel-src {r2.intf_addrs['eth2'].ip} tunnel-dst {r1.intf_addrs['eth2'].ip} "
        + out_iptfs_opts
        # " use-esn use-anti-replay",
    )
    vppctl_raises(
        r2, f"vppctl ipsec tunnel protect ipsec0 sa-in {reqid_1to2} sa-out {reqid_2to1}"
    )
    vppctl_raises(r2, "vppctl set interface unnumbered ipsec0 use UnknownEthernet2")
    vppctl_raises(r2, "vppctl set interface state ipsec0 up")

    vppctl_raises(r2, "vppctl ip route add 10.0.0.0/24 via ipsec0")
    # vppctl_raises(r2, "vppctl ip route add 10.0.1.0/24 via ipsec0")


async def test_policy_tun(unet, astepf):
    h1 = unet.hosts["h1"]

    use_tfs = True
    use_gcm = True
    enc_null = False
    use_nullnull = False

    await setup_vpp_ipsec(
        unet,
        use_tfs=use_tfs,
        use_gcm=use_gcm,
        enc_null=enc_null,
        use_nullnull=use_nullnull,
    )
    await setup_policy_tun(
        unet,
        mode="iptfs" if use_tfs else "tunnel",
        use_gcm=use_gcm,
        r1only=True,
        enc_null=enc_null,
        use_nullnull=use_nullnull,
    )

    await astepf("first ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    await astepf("second ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    await astepf("third ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))


async def _test_iptfs_policy_tun_up(
    unet, use_tfs=True, use_gcm=True, use_nullnull=False, enc_null=False
):
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]
    h1 = unet.hosts["h1"]
    r1repl = r1.conrepl

    setup_vpp_ipsec(unet)
    setup_policy_tun(unet, r1only=True)

    # for r, repl in [(r1, r1repl), (r2, r2repl)]:
    #     repl.cmd_raises("ip link set lo up")
    #     repl.cmd_raises("ip link set eth0 up")
    #     repl.cmd_status(f"""ip addr add {r.intf_addrs["eth0"]} dev eth0""")

    if not use_gcm:
        if use_nullnull:
            rspi = 0xAAAAAA
            lspi = 0xBBBBBB
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
            # "0x4a506a794f574265564551694d653768"
            # "4a506a794f574265564551694d6537681A2B1A2B "
            # "256"
        )

    r1ipp = r1.intf_addrs["eth2"]
    r1ip = r1ipp.ip
    r1ipp = r1ipp.network

    r2ipp = r2.intf_addrs["eth2"]
    r2ip = r2ipp.ip
    r2ipp = r2ipp.network

    #
    # SAs
    #
    # +----+  --- iptfs---> +----+
    # | r1 | <-- ipsec ---  | r2 |
    # +----+                +----+
    #
    r1repl.cmd_status("ip x s deleteall")
    r1repl.cmd_status("ip x p deleteall")

    r1repl.cmd_raises(
        f"ip xfrm state add src {r1ip} dst {r2ip} proto esp "
        f"spi {rspi} mode iptfs {sa_auth} {sa_enc} "
        f"reqid 0x10"
    )
    r1repl.cmd_raises(
        f"ip xfrm state add src {r2ip} dst {r1ip} proto esp "
        f"spi {lspi} mode tunnel {sa_auth} {sa_enc} "
        f"reqid 0x11"
    )

    #
    # Policy
    #
    for x1ipp, x2ipp in [
        ("10.0.0.0/24", "10.0.1.0/24"),  # host to router
        # ("10.0.1.0/24", "10.0.1.0/24"),  # router to router
        # ("10.0.1.0/24", "10.0.2.0/24"),  # host to router
        ("10.0.0.0/24", "10.0.2.0/24"),  # host to host
    ]:
        direction = "dir out"
        r1repl.cmd_raises(
            f"ip xfrm policy add src {x1ipp} dst {x2ipp} {direction} "
            f"tmpl src {r1ip} dst {r2ip} proto esp mode iptfs "
            f"reqid 0x10",
            # " spi {rspi} "
        )
        for direction in ["dir fwd", "dir in"]:
            r1repl.cmd_raises(
                f"ip xfrm policy add src {x2ipp} dst {x1ipp} {direction} "
                f"tmpl src {r2ip} dst {r1ip} proto esp mode tunnel "
                f"reqid 0x11",
                # " spi {lspi} "
            )

    # Need to count ESP packets somehow to verify these were encrypted

    # logging.debug(h1.cmd_raises("ping -w1 -i.2 -c1 10.0.1.3"))
    # logging.debug(h1.cmd_raises("ping -w1 -i.2 -c1 10.0.2.3"))
    await astepf("first ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    await astepf("second ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))
    await astepf("third ping")
    logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))

    # logging.debug(r1repl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.3"))
    # logging.debug(r1repl.cmd_raises("ping -w1 -i.2 -c1 10.0.2.3"))
    # logging.debug(r1repl.cmd_raises("ping -w1 -i.2 -c1 10.0.2.4"))

    # await async_cli(unet)
