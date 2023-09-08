# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# September 17 2022, Christian Hopps <chopps@labn.net>
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
"Common code for configuring tests."

import binascii
import ipaddress
import os
import shlex

from . import iptfs

g_offloads = [
    # These are both required on my machine to get rid of GSO
    # "generic-receive-offload",
    # "rx-gro-hw",
    #     # These are not required to get rid of GSO in iptfs path
    #     # "generic-segmentation-offload",
    #     # "tcp-segmentation-offload",
    #     # "tx-gso-partial",
]


async def ethtool_disable_if_offloads(node, ifname, offloads):
    for offload in offloads:
        node.conrepl.cmd_raises(f"ethtool -K {ifname} {offload} off")


async def ethtool_disable_offloads(node, offloads):
    for ifname in node.intfs:
        await ethtool_disable_if_offloads(node, ifname, offloads)


async def _network_up(
    unet, trex=False, r1only=False, ipv4=True, ipv6=False, minimal=False
):
    h1 = unet.hosts.get("h1")
    h2 = unet.hosts.get("h2")
    r1 = unet.hosts.get("r1")
    r2 = unet.hosts.get("r2") if not r1only else None

    r1con = r1.conrepl if r1 else None
    r2con = r2.conrepl if r2 else None

    await ethtool_disable_offloads(r1, g_offloads)
    if r2:
        await ethtool_disable_offloads(r2, g_offloads)

    await toggle_ipv6(unet, enable=ipv6)
    await toggle_forward_pmtu(unet, enable=False)
    await toggle_forwarding(unet, enable=True)

    await toggle_ipv6(unet, enable=ipv6)

    if ipv4:
        if h1:
            h1.cmd_raises("ip route add 10.0.2.0/24 via 10.0.0.2")
            h1.cmd_raises("ip route add 10.0.1.0/24 via 10.0.0.2")

        if not minimal:
            if r1con and not trex:
                r1con.cmd_raises("ip route add 10.0.2.0/24 via 10.0.1.3 mtu 65536")
            elif r1con:
                # local route
                r1con.cmd_raises("ip route add 16.0.0.0/8 via 11.0.0.1")
                # remote routes
                r1con.cmd_raises("ip route add 12.0.0.0/24 via 10.0.1.3")
                r1con.cmd_raises("ip route add 48.0.0.0/8 via 10.0.1.3")

            if r2con and not trex:
                r2con.cmd_raises("ip route add 10.0.0.0/24 via 10.0.1.2 mtu 65536")
            elif r2con:
                # remote routes
                r2con.cmd_raises("ip route add 11.0.0.0/24 via 10.0.1.2")
                r2con.cmd_raises("ip route add 16.0.0.0/8 via 10.0.1.2")
                # local route
                r2con.cmd_raises("ip route add 48.0.0.0/8 via 12.0.0.1")

        if h2:
            h2.cmd_raises("ip route add 10.0.1.0/24 via 10.0.2.3")
            h2.cmd_raises("ip route add 10.0.0.0/24 via 10.0.2.3")

    if ipv6:
        if h1:
            h1.cmd_raises("ip -6 route add fc00:0:0:2::/64 via fc00:0:0:0::2")
            h1.cmd_raises("ip -6 route add fc00:0:0:1::/64 via fc00:0:0:0::2")

        if not minimal:
            if r1con and not trex:
                r1con.cmd_raises(
                    "ip -6 route add fc00:0:0:2::/64 via fc00:0:0:1::3 mtu 65536"
                )
            elif r1con:
                r1con.cmd_raises("ip -6 route add 2012::/64 via fc00:0:0:1::3")
                # r1con.cmd_raises("ip -6 route add 2016::/64 via fc00:0:0:11::1")
                r1con.cmd_raises("ip -6 route add 2048::/16 via fc00:0:0:1::3")

            if r2con and not trex:
                r2con.cmd_raises(
                    "ip -6 route add fc00:0:0:0::/64 via fc00:0:0:1::2 mtu 65536"
                )
            elif r2:
                r2con.cmd_raises("ip -6 route add 2011::/64 via fc00:0:0:1::2")
                r2con.cmd_raises("ip -6 route add 2016::/16 via fc00:0:0:1::2")
                # r2con.cmd_raises("ip -6 route add 2048::/64 via fc00:0:0:12::1")

        if h2:
            h2.cmd_raises("ip -6 route add fc00:0:0:1::/64 via fc00:0:0:2::3")
            h2.cmd_raises("ip -6 route add fc00:0:0:0::/64 via fc00:0:0:2::3")


async def cleanup_config(unet, r1only=False, ipv4=True, ipv6=False):
    r1 = unet.hosts.get("r1")
    r1con = r1.conrepl if r1 else None

    r2 = unet.hosts.get("r2") if not r1only else None
    r2con = r2.conrepl if r2 else None

    r1con.cmd_nostatus("ip link del ipsec0")
    if not r1only:
        r2con.cmd_nostatus("ip link del ipsec0")

    if ipv4:
        r1con.cmd_nostatus("ip route del 10.0.2.0/24 dev ipsec0")
        r1con.cmd_nostatus("ip route del 12.0.0.0/24 dev ipsec0")
        r1con.cmd_nostatus("ip route del 48.0.0.0/8 dev ipsec0")

        if r2 and not r1only:
            r2con.cmd_nostatus("ip route del 10.0.0.0/24 dev ipsec0")
            r2con.cmd_nostatus("ip route del 11.0.0.0/24 dev ipsec0")
            r2con.cmd_nostatus("ip route del 16.0.0.0/8 dev ipsec0")

        r1con.cmd_nostatus("ip route del 10.0.2.0/24 via 10.0.1.3")
        r1con.cmd_nostatus("ip route del 12.0.0.0/24 via 10.0.1.3")
        r1con.cmd_nostatus("ip route del 48.0.0.0/8 via 10.0.1.3")

        if r2 and not r1only:
            r2con.cmd_nostatus("ip route del 10.0.0.0/24 via 10.0.1.2")
            r2con.cmd_nostatus("ip route del 11.0.0.0/24 via 10.0.1.2")
            r2con.cmd_nostatus("ip route del 16.0.0.0/8 via 10.0.1.2")

    if ipv6:
        r1con.cmd_nostatus("ip route del fc00:0:0:2::/64 dev ipsec0")
        r1con.cmd_nostatus("ip route del 2012::/64 dev ipsec0")
        r1con.cmd_nostatus("ip route del 2048::/16 dev ipsec0")

        if r2 and not r1only:
            r2con.cmd_nostatus("ip route del fc00:0:0:0::/64 dev ipsec0")
            r2con.cmd_nostatus("ip route del 2011::/64 dev ipsec0")
            r2con.cmd_nostatus("ip route del 2016::/16 dev ipsec0")

        r1con.cmd_nostatus("ip route del fc00:0:0:2::/64 via fc00:0:0:1::3")
        r1con.cmd_nostatus("ip route del 2012::/64 via fc00:0:0:1::3")
        r1con.cmd_nostatus("ip route del 2048::/16 via fc00:0:0:1::3")

        if r2 and not r1only:
            r2con.cmd_nostatus("ip route del fc00:0:0:0::/64 via fc00:0:0:1::2")
            r2con.cmd_nostatus("ip route del 2011::/64 via fc00:0:0:1::2")
            r2con.cmd_nostatus("ip route del 2016::/16 via fc00:0:0:1::2")

    r1con.cmd_nostatus("ip x s deleteall")
    r1con.cmd_nostatus("ip x p deleteall")

    if not r1only:
        r2con.cmd_nostatus("ip x s deleteall")
        r2con.cmd_nostatus("ip x p deleteall")


#                             192.168.0.0/24
#   --+-----------------+------ mgmt0 ----+-----------------+-----------------------
#     | .1              | .2              | .3              | .4              | .5
#   +----+            +----+            +----+            +----+            +----+
#   | h1 | -- net0 -- | r1 | -- net1 -- | rm | -- net2 -- | r2 | -- net2 -- | h1 |
#   +----+ .1      .2 +----+ .2      .3 +----+ .3      .4 +----+ .4      .5 +----+
#          10.0.0.0/24       10.0.1.0/24       10.0.2.0/24       10.0.3.0/24


async def _network_up3(unet, ipv4=True, ipv6=False, trex=False, minimal=False):
    h1 = unet.hosts.get("h1")
    h2 = unet.hosts.get("h2")
    r1 = unet.hosts.get("r1")
    rm = unet.hosts.get("rm")
    r2 = unet.hosts.get("r2")

    if r1:
        await ethtool_disable_offloads(r1, g_offloads)
    if r2:
        await ethtool_disable_offloads(r2, g_offloads)

    await toggle_ipv6(unet, enable=ipv6)
    await toggle_forward_pmtu(unet, enable=False)
    await toggle_forwarding(unet, enable=True)

    if h1:
        if ipv4:
            h1.cmd_raises("ip route add 10.0.3.0/24 via 10.0.0.2")
            h1.cmd_raises("ip route add 10.0.2.0/24 via 10.0.0.2")
            h1.cmd_raises("ip route add 10.0.1.0/24 via 10.0.0.2")

        if ipv6:
            h1.cmd_raises("ip -6 route add fc00:0:0:3::/64 via fc00:0:0:0::2")
            h1.cmd_raises("ip -6 route add fc00:0:0:2::/64 via fc00:0:0:0::2")
            h1.cmd_raises("ip -6 route add fc00:0:0:1::/64 via fc00:0:0:0::2")

    # minimal routing between r1 and r2 though rm
    r1con = r1.conrepl if r1 else None
    if r1:
        if ipv4:
            r1con.cmd_raises("ip route add 10.0.2.0/24 via 10.0.1.3")
        if ipv6:
            r1con.cmd_raises("ip -6 route add fc00:0:0:2::/64 via fc00:0:0:1::3")

    if r1 and not minimal:
        if ipv4:
            if not trex:
                r1con.cmd_raises("ip route add 10.0.3.0/24 via 10.0.1.3")
            else:
                r1con.cmd_raises("ip route add 12.0.0.0/24 via 10.0.1.3")
                r1con.cmd_raises("ip route add 48.0.0.0/8 via 10.0.1.3")
        if ipv6:
            if not trex:
                r1con.cmd_raises("ip -6 route add fc00:0:0:3::/64 via fc00:0:0:1::3")
            else:
                r1con.cmd_raises("ip -6 route add 2012::/64 via fc00:0:0:1::3")
                r1con.cmd_raises("ip -6 route add 2048::/16 via fc00:0:0:1::3")

    if rm and not minimal:
        if ipv4:
            if not trex:
                rm.cmd_raises("ip route add 10.0.0.0/24 via 10.0.1.2")
                rm.cmd_raises("ip route add 10.0.3.0/24 via 10.0.2.4")
            else:
                rm.cmd_raises("ip route add 11.0.0.0/24 via 10.0.1.2")
                rm.cmd_raises("ip route add 16.0.0.0/8 via 10.0.1.2")
                rm.cmd_raises("ip route add 12.0.0.0/24 via 10.0.2.4")
                rm.cmd_raises("ip route add 48.0.0.0/8 via 10.0.2.4")
        if ipv6:
            if not trex:
                rm.cmd_raises("ip -6 route add fc00:0:0:0::/64 via fc00:0:0:1::2")
                rm.cmd_raises("ip -6 route add fc00:0:0:3::/64 via fc00:0:0:2::4")
            else:
                rm.cmd_raises("ip -6 route add 2011::/64 via fc00:0:0:1::2")
                rm.cmd_raises("ip -6 route add 2016::/16 via fc00:0:0:1::2")
                rm.cmd_raises("ip -6 route add 2012::/64 via fc00:0:0:2::4")
                rm.cmd_raises("ip -6 route add 2048::/16 via fc00:0:0:2::4")

    # minimal routing between r1 and r2 though rm
    r2con = r2.conrepl if r2 else None
    if r2:
        if ipv4:
            r2con.cmd_raises("ip route add 10.0.1.0/24 via 10.0.2.3")
        if ipv6:
            r2con.cmd_raises("ip -6 route add fc00:0:0:1::/64 via fc00:0:0:2::3")

    if r2 and not minimal:
        if ipv4:
            if not trex:
                r2con.cmd_raises("ip route add 10.0.0.0/24 via 10.0.2.3")
            else:
                r2con.cmd_raises("ip route add 11.0.0.0/24 via 10.0.2.3")
                r2con.cmd_raises("ip route add 16.0.0.0/8 via 10.0.2.3")
        if ipv6:
            if not trex:
                r2con.cmd_raises("ip -6 route add fc00:0:0:0::/64 via fc00:0:0:2::3")
                r2con.cmd_raises("ip -6 route add fc00:0:0:1::/64 via fc00:0:0:2::3")
            else:
                r2con.cmd_raises("ip -6 route add 2011::/64 via fc00:0:0:2::3")
                r2con.cmd_raises("ip -6 route add 2016::/16 via fc00:0:0:2::3")
    if h2:
        if ipv4:
            h2.cmd_raises("ip route add 10.0.2.0/24 via 10.0.3.4")
            h2.cmd_raises("ip route add 10.0.1.0/24 via 10.0.3.4")
            h2.cmd_raises("ip route add 10.0.0.0/24 via 10.0.3.4")
        if ipv6:
            h2.cmd_raises("ip -6 route add fc00:0:0:2::/64 via fc00:0:0:3::4")
            h2.cmd_raises("ip -6 route add fc00:0:0:1::/64 via fc00:0:0:3::4")
            h2.cmd_raises("ip -6 route add fc00:0:0:0::/64 via fc00:0:0:3::4")


async def cleanup_config3(unet, ipv4=True, ipv6=False):
    r1 = unet.hosts.get("r1")
    r2 = unet.hosts.get("r2")
    if r1 := unet.hosts.get("r1"):
        r1con = r1.conrepl
        if ipv4:
            # The route used by the tunnel packets
            r1con.cmd_nostatus("ip route del 10.0.2.4/32 via 10.0.1.3")

            r1con.cmd_nostatus("ip route del 10.0.2.0/24 dev ipsec0")
            r1con.cmd_nostatus("ip route del 10.0.3.0/24 dev ipsec0")
            r1con.cmd_nostatus("ip route del 12.0.0.0/24 dev ipsec0")
            r1con.cmd_nostatus("ip route del 48.0.0.0/8 dev ipsec0")

            r1con.cmd_nostatus("ip route del 10.0.2.0/24 via 10.0.1.3")
            r1con.cmd_nostatus("ip route del 10.0.3.0/24 via 10.0.1.3")
            r1con.cmd_nostatus("ip route del 12.0.0.0/24 via 10.0.1.3")
            r1con.cmd_nostatus("ip route del 48.0.0.0/8 via 10.0.1.3")

        if ipv6:
            # The route used by the tunnel packets
            r1con.cmd_nostatus("ip route del fc00:0:0:2::4/128 via fc00:0:0:1::3")

            r1con.cmd_nostatus("ip route del fc00:0:0:2::/64 dev ipsec0")
            r1con.cmd_nostatus("ip route del fc00:0:0:3::/64 dev ipsec0")
            r1con.cmd_nostatus("ip route del 2012::/64 dev ipsec0")
            r1con.cmd_nostatus("ip route del 2048::/16 dev ipsec0")

            r1con.cmd_nostatus("ip -6 route del fc00:0:0:2::/64 via fc00:0:0:1::3")
            r1con.cmd_nostatus("ip -6 route del fc00:0:0:3::/64 via fc00:0:0:1::3")
            r1con.cmd_nostatus("ip -6 route del 2012::/64 via fc00:0:0:1::3")
            r1con.cmd_nostatus("ip -6 route del 2048::/16 via fc00:0:0:1::3")

        r1con.cmd_nostatus("ip link del ipsec0")
        r1con.cmd_nostatus("ip x s deleteall")
        r1con.cmd_nostatus("ip x p deleteall")

    if r2 := unet.hosts.get("r2"):
        r2con = r2.conrepl
        if ipv4:
            # The route used by the tunnel packets
            r2con.cmd_nostatus("ip route del 10.0.1.2/32 via 10.0.2.3")

            r2con.cmd_nostatus("ip route del 10.0.1.0/24 dev ipsec0")
            r2con.cmd_nostatus("ip route del 10.0.0.0/24 dev ipsec0")
            r2con.cmd_nostatus("ip route del 11.0.0.0/24 dev ipsec0")
            r2con.cmd_nostatus("ip route del 16.0.0.0/8 dev ipsec0")

            r2con.cmd_nostatus("ip route del 10.0.0.0/24 via 10.0.2.3")
            r2con.cmd_nostatus("ip route del 10.0.1.0/24 via 10.0.2.3")
            r2con.cmd_nostatus("ip route del 11.0.0.0/24 via 10.0.2.3")
            r2con.cmd_nostatus("ip route del 16.0.0.0/8 via 10.0.2.3")

        if ipv6:
            # The route used by the tunnel packets
            r2con.cmd_nostatus("ip route del fc00:0:0:1::2/128 via fc00:0:0:2::3")

            r2con.cmd_nostatus("ip route del fc00:0:0:1::/64 dev ipsec0")
            r2con.cmd_nostatus("ip route del fc00:0:0:0::/64 dev ipsec0")
            r2con.cmd_nostatus("ip route del 2011::/64 dev ipsec0")
            r2con.cmd_nostatus("ip route del 2016::/16 dev ipsec0")

            r2con.cmd_nostatus("ip -6 route del fc00:0:0:1::/64 via fc00:0:0:2::3")
            r2con.cmd_nostatus("ip -6 route del fc00:0:0:0::/64 via fc00:0:0:2::3")
            r2con.cmd_nostatus("ip -6 route del 2011::/64 via fc00:0:0:2::3")
            r2con.cmd_nostatus("ip -6 route del 2016::/16 via fc00:0:0:2::3")

        r2con.cmd_nostatus("ip link del ipsec0")
        r2con.cmd_nostatus("ip x s deleteall")
        r2con.cmd_nostatus("ip x p deleteall")


async def toggle_forward_pmtu(unet, enable=False):
    nodes = list(unet.hosts.values())
    if unet.isolated:
        nodes.append(unet)
    for node in nodes:
        if enable:
            node.cmd_raises("sysctl -w net.ipv4.ip_forward_use_pmtu=1")
        else:
            node.cmd_raises("sysctl -w net.ipv4.ip_forward_use_pmtu=0")


async def toggle_forwarding(unet, enable=False):
    nodes = list(unet.hosts.values())
    if unet.isolated:
        nodes.append(unet)
    for node in nodes:
        if enable:
            node.cmd_raises("sysctl -w net.ipv4.ip_forward=1")
            node.cmd_raises("sysctl -w net.ipv6.conf.all.forwarding=1")
        else:
            node.cmd_raises("sysctl -w net.ipv4.ip_forward=0")
            node.cmd_raises("sysctl -w net.ipv6.conf.all.forwarding=0")


async def toggle_ipv6(unet, enable=False):
    nodes = list(unet.hosts.values())
    if unet.isolated:
        nodes.append(unet)
    for node in nodes:
        if hasattr(node, "conrepl") and node.conrepl:
            node = node.conrepl
        if enable:
            node.cmd_raises("sysctl -w net.ipv6.conf.all.autoconf=1")
            node.cmd_raises("sysctl -w net.ipv6.conf.all.disable_ipv6=0")
            node.cmd_raises("sysctl -w net.ipv6.conf.all.forwarding=1")
            # node.cmd_raises("sysctl -w net.ipv6.conf.all.mc_forwarding=1")
        else:
            node.cmd_raises("sysctl -w net.ipv6.conf.all.autoconf=0")
            node.cmd_raises("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
            node.cmd_raises("sysctl -w net.ipv6.conf.all.forwarding=0")
            # node.cmd_raises("sysctl -w net.ipv6.conf.all.mc_forwarding=0")


def get_sa_values(use_gcm=True, use_nullnull=False, enc_null=False, tun_ipv6=False):
    if use_nullnull:
        spi_1to2 = 0xAAAAAA
        spi_2to1 = 0xBBBBBB
        sa_auth = 'auth digest_null ""'
        sa_enc = 'enc cipher_null ""'
    elif use_gcm:
        spi_1to2 = 0xAAA
        spi_2to1 = 0xBBB
        sa_auth = ""
        sa_enc = (
            'aead "rfc4106(gcm(aes))" '
            # 'aead "seqiv(rfc4106(gcm(aes)))" '
            "0x4a506a794f574265564551694d6537681A2B1A2B "
            "128"
            # "0x4a506a794f574265564551694d6537684a"
            # "506a794f574265564551694d6537681A2B1A2B "
            # "256"
        )
    elif enc_null:
        spi_1to2 = 0xAAAA
        spi_2to1 = 0xBBBB
        # sa_auth = "auth sha256 0x0123456789ABCDEF0123456789ABCDEF"
        # "0123456789ABCDEF0123456789ABCDEF"
        # sa_auth = "auth sha256 0x0123456789ABCDEF0123456789ABCDEF"
        sa_auth = "auth 'hmac(sha1)' 0x0123456789ABCDEF0123456789ABCDEF01234567"
        sa_enc = 'enc cipher_null ""'
    else:
        spi_1to2 = 0xAA
        spi_2to1 = 0xBB
        # sa_auth = "auth sha256 0x0123456789ABCDEF0123456789ABCDEF"
        # "0123456789ABCDEF0123456789ABCDEF"
        # sa_auth = "auth sha256 0x0123456789ABCDEF0123456789ABCDEF"
        sa_auth = "auth 'hmac(sha1)' 0x0123456789ABCDEF0123456789ABCDEF01234567"
        sa_enc = "enc 'cbc(aes)' 0xFEDCBA9876543210FEDCBA9876543210"
    if tun_ipv6:
        return 0x80000000 | spi_1to2, 0x80000000 | spi_2to1, sa_auth, sa_enc
    return spi_1to2, spi_2to1, sa_auth, sa_enc


def setup_tunnel_routes(r1con, r2con, tun_ipv6, network3):
    if not network3:
        r1ipnh = "via 10.0.1.3"
        r2ipnh = "via 10.0.1.2"
        r1ip6nh = "via fc00:0:0:1::3"
        r2ip6nh = "via fc00:0:0:1::2"
    else:
        r1ipnh = "via 10.0.1.3"
        r2ipnh = "via 10.0.2.3"
        r1ip6nh = "via fc00:0:0:1::3"
        r2ip6nh = "via fc00:0:0:2::3"
        #
        # Setup multi-hop routes for tunnel packets
        #
        if not tun_ipv6:
            if r1con:
                r1con.cmd_raises(f"ip route add 10.0.2.4/32 {r1ipnh}")
            if r2con:
                r2con.cmd_raises(f"ip route add 10.0.1.2/32 {r2ipnh}")
        else:
            if r1con:
                r1con.cmd_raises(f"ip route add fc00:0:0:2::4/128 {r1ip6nh}")
            if r2con:
                r2con.cmd_raises(f"ip route add fc00:0:0:1::2/128 {r2ip6nh}")
    return r1ipnh, r1ip6nh, r2ipnh, r2ip6nh


async def setup_policy_tun(
    unet,
    mode=None,
    use_gcm=True,
    use_nullnull=False,
    enc_null=False,
    trex=False,
    r1only=False,
    ipsec_intf="eth2",
    esp_flags="",
    iptfs_opts="",
    ipv4=True,
    ipv6=False,
    tun_ipv6=False,
    network3=False,
    tun_route_mtu=None,
):
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"] if "r2" in unet.hosts else None

    if not mode:
        mode = os.environ.get("IPSEC_MODE", "iptfs")

    if not iptfs_opts:
        iptfs_opts = os.environ.get("IPTFS_OPTS", "")

    if iptfs_opts:
        iptfs_opts = "iptfs-opts " + iptfs_opts

    if tun_ipv6:
        reqid_1to2 = 0x12
        reqid_2to1 = 0x13
    else:
        reqid_1to2 = 0x10
        reqid_2to1 = 0x11

    spi_1to2, spi_2to1, sa_auth, sa_enc = get_sa_values(
        use_gcm, use_nullnull, enc_null, tun_ipv6=tun_ipv6
    )

    r1ipp = r1.get_intf_addr(ipsec_intf, ipv6=tun_ipv6)
    if r2 is not None:
        r2ipp = r2.get_intf_addr(ipsec_intf, ipv6=tun_ipv6)
    else:
        # The other side is the switch interface
        net = None
        for net in r1.net_intfs:
            if r1.net_intfs[net] == ipsec_intf:
                break
        assert net is not None, f"can't find network for {ipsec_intf}"
        if tun_ipv6:
            r2ipp = unet.switches[net].ip6_interface
        else:
            r2ipp = unet.switches[net].ip_interface

    r1ip = r1ipp.ip
    r1ipp = r1ipp.network
    r2ip = r2ipp.ip
    r2ipp = r2ipp.network

    # Start with a clean slate
    if network3:
        await cleanup_config3(unet, ipv4=ipv4, ipv6=ipv6)
    else:
        await cleanup_config(unet, r1only=r1only, ipv4=ipv4, ipv6=ipv6)

    if bool(tun_ipv6) != bool(ipv6):
        esp_flags = "af-unspec " + esp_flags
    if esp_flags:
        esp_flags = "flag " + esp_flags

    for r in (r1, r2) if not r1only else (r1,):
        repl = r.conrepl

        #
        # SAs
        #
        repl.cmd_raises(
            (
                f"ip xfrm state add src {r1ip} dst {r2ip} proto esp "
                f"spi {spi_1to2} mode {mode} {sa_auth} {sa_enc} "
                f"{esp_flags} reqid {reqid_1to2} "
                # f"reqid {reqid_1to2} "
            )
            + iptfs_opts
        )
        repl.cmd_raises(
            (
                f"ip xfrm state add src {r2ip} dst {r1ip} proto esp "
                f"spi {spi_2to1} mode {mode} {sa_auth} {sa_enc} "
                f"{esp_flags} reqid {reqid_2to1} "
                # f"reqid {reqid_2to1} "
            )
            + iptfs_opts
        )

        #
        # Policy
        #
        def policy_add(iplist, r, repl):
            for x1ipp, x2ipp in iplist:
                for direction in ["dir out"] if r == r1 else ["dir fwd", "dir in"]:
                    repl.cmd_raises(
                        f"ip xfrm policy add src {x1ipp} dst {x2ipp} {direction} "
                        f"tmpl src {r1ip} dst {r2ip} proto esp mode {mode} "
                        f"reqid {reqid_1to2}",
                        # " spi {spi_1to2} "
                    )
                for direction in ["dir out"] if r == r2 else ["dir fwd", "dir in"]:
                    repl.cmd_raises(
                        f"ip xfrm policy add src {x2ipp} dst {x1ipp} {direction} "
                        f"tmpl src {r2ip} dst {r1ip} proto esp mode {mode} "
                        f"reqid {reqid_2to1}",
                        # " spi {spi_2to1} "
                    )

        iplist = []
        if ipv4 and not network3:
            if not trex:
                iplist += [
                    ("10.0.0.0/24", "10.0.1.0/24"),  # host to router
                    ("10.0.1.0/24", "10.0.1.0/24"),  # router to router
                    ("10.0.1.0/24", "10.0.2.0/24"),  # host to router
                    ("10.0.0.0/24", "10.0.2.0/24"),  # host to host
                ]
            else:
                iplist += [
                    ("10.0.1.0/24", "10.0.1.0/24"),  # router to router
                    ("11.0.0.0/24", "12.0.0.0/24"),  # host to host
                    ("16.0.0.0/8", "48.0.0.0/8"),  # host to host
                ]
        if ipv6 and not network3:
            if not trex:
                iplist += [
                    ("fc00:0:0:0::/64", "fc00:0:0:1::/64"),  # host to router
                    ("fc00:0:0:1::/64", "fc00:0:0:1::/64"),  # router to router
                    ("fc00:0:0:1::/64", "fc00:0:0:2::/64"),  # host to router
                    ("fc00:0:0:0::/64", "fc00:0:0:2::/64"),  # host to host
                ]
            else:
                iplist += [
                    ("fc00:0:0:1::/64", "fc00:0:0:1::/64"),  # router to router
                    ("2011::/64", "2012::/64"),  # host to host
                    ("2016::/16", "2048::/16"),  # host to host
                ]

        # KISS this and only support host network to host network encap
        if ipv4 and network3:
            if not trex:
                iplist += [
                    ("10.0.0.0/24", "10.0.3.0/24"),  # host to host
                    ("10.0.0.0/24", "10.0.2.0/24"),  # host to router
                    ("10.0.1.0/24", "10.0.2.0/24"),  # host to router
                    ("10.0.1.0/24", "10.0.3.0/24"),  # host to host
                ]
            else:
                iplist += [
                    ("11.0.0.0/24", "12.0.0.0/24"),  # host to host
                    ("16.0.0.0/8", "48.0.0.0/8"),  # host to host
                ]
        if ipv6 and network3:
            if not trex:
                iplist += [
                    ("fc00:0:0:0::/64", "fc00:0:0:3::/64"),  # host to host
                    ("fc00:0:0:0::/64", "fc00:0:0:2::/64"),  # host to router
                    ("fc00:0:0:1::/64", "fc00:0:0:2::/64"),  # host to router
                    ("fc00:0:0:1::/64", "fc00:0:0:3::/64"),  # host to router
                ]
            else:
                iplist += [
                    ("2011::/64", "2012::/64"),  # host to host
                    ("2016::/16", "2048::/16"),  # host to host
                ]

        policy_add(iplist, r, repl)

    r1con = r1.conrepl if r1 else None
    r2con = r2.conrepl if r2 and not r1only else None

    mtustr = f"mtu {tun_route_mtu}" if tun_route_mtu else ""

    r1ipnh, r1ip6nh, r2ipnh, r2ip6nh = setup_tunnel_routes(
        r1con, r2con, tun_ipv6, network3
    )

    #
    # Setup inner traffic routes
    #
    if ipv4:
        if not trex:
            if r1con:
                r1con.cmd_raises(f"ip route add 10.0.2.0/24 {r1ipnh} {mtustr}")
                if network3:
                    r1con.cmd_raises(f"ip route add 10.0.3.0/24 {r1ipnh} {mtustr}")
            if r2con:
                r2con.cmd_raises(f"ip route add 10.0.0.0/24 {r2ipnh} {mtustr}")
                if network3:
                    r2con.cmd_raises(f"ip route add 10.0.1.0/24 {r2ipnh} {mtustr}")
        else:
            if r1con:
                r1con.cmd_raises(f"ip route add 12.0.0.0/24 {r1ipnh} {mtustr}")
                r1con.cmd_raises(f"ip route add 48.0.0.0/8 {r1ipnh} {mtustr}")
            if r2con:
                r2con.cmd_raises(f"ip route add 11.0.0.0/24 {r2ipnh} {mtustr}")
                r2con.cmd_raises(f"ip route add 16.0.0.0/8 {r2ipnh} {mtustr}")
    if ipv6:
        if not trex:
            if r1con:
                r1con.cmd_raises(f"ip route add fc00:0:0:2::/64 {r1ip6nh} {mtustr}")
                if network3:
                    r1con.cmd_raises(f"ip route add fc00:0:0:3::/64 {r1ip6nh} {mtustr}")
            if r2con:
                r2con.cmd_raises(f"ip route add fc00:0:0:0::/64 {r2ip6nh} {mtustr}")
                if network3:
                    r2con.cmd_raises(f"ip route add fc00:0:0:1::/64 {r2ip6nh} {mtustr}")
        else:
            if r1con:
                r1con.cmd_raises(f"ip route add 2012::/64 {r1ip6nh} {mtustr}")
                r1con.cmd_raises(f"ip route add 2048::/16 {r1ip6nh} {mtustr}")

            if r2con:
                r2con.cmd_raises(f"ip route add 2011::/64 {r2ip6nh} {mtustr}")
                r2con.cmd_raises(f"ip route add 2016::/16 {r2ip6nh} {mtustr}")


async def setup_routed_tun(
    unet,
    mode=None,
    use_gcm=True,
    use_nullnull=False,
    enc_null=False,
    trex=False,
    r1only=False,
    ipsec_intf="eth2",
    iptfs_opts="",
    esp_flags="",
    ipv4=True,
    ipv6=False,
    tun_ipv6=False,
    network3=False,
    tun_route_mtu=None,
):
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"] if "r2" in unet.hosts else None

    if not mode:
        mode = os.environ.get("IPSEC_MODE", "iptfs")

    if not iptfs_opts:
        iptfs_opts = os.environ.get("IPTFS_OPTS", "")

    if iptfs_opts:
        iptfs_opts = "iptfs-opts " + iptfs_opts

    if tun_ipv6:
        reqid_1to2 = 0xA
        reqid_2to1 = 0xB
    else:
        reqid_1to2 = 8
        reqid_2to1 = 9

    spi_1to2, spi_2to1, sa_auth, sa_enc = get_sa_values(
        use_gcm, use_nullnull, enc_null, tun_ipv6=tun_ipv6
    )

    r1ipp = r1.get_intf_addr(ipsec_intf, ipv6=tun_ipv6)
    if r2 is not None:
        r2ipp = r2.get_intf_addr(ipsec_intf, ipv6=tun_ipv6)
    else:
        # The other side is the switch interface
        net = None
        for net in r1.net_intfs:
            if r1.net_intfs[net] == ipsec_intf:
                break
        assert net is not None, f"can't find network for {ipsec_intf}"
        if tun_ipv6:
            r2ipp = unet.switches[net].ip6_interface
        else:
            r2ipp = unet.switches[net].ip_interface

    r1ip = r1ipp.ip
    r1ipp = r1ipp.network
    r2ip = r2ipp.ip
    r2ipp = r2ipp.network

    # Start with a clean slate
    if network3:
        await cleanup_config3(unet, ipv4=ipv4, ipv6=ipv6)
    else:
        await cleanup_config(unet, r1only=r1only, ipv4=ipv4, ipv6=ipv6)

    if bool(tun_ipv6) != bool(ipv6):
        esp_flags = "af-unspec " + esp_flags
    if esp_flags:
        esp_flags = "flag " + esp_flags

    for r in (r1, r2) if not r1only else (r1,):
        repl = r.conrepl
        #
        # SAs
        #
        if r == r1:
            oreqid, ireqid = reqid_1to2, reqid_2to1
            lip = r1ip
            rip = r2ip
        else:
            oreqid, ireqid = reqid_2to1, reqid_1to2
            lip = r2ip
            rip = r1ip

        repl.cmd_raises(
            (
                f"ip xfrm state add src {r1ip} dst {r2ip} proto esp "
                f"spi {spi_1to2} mode {mode} {sa_auth} {sa_enc} "
                f"{esp_flags} if_id 55 reqid {reqid_1to2} "
            )
            + iptfs_opts
        )
        repl.cmd_raises(
            (
                f"ip xfrm state add src {r2ip} dst {r1ip} proto esp "
                f"spi {spi_2to1} mode {mode} {sa_auth} {sa_enc} "
                f"{esp_flags} if_id 55 reqid {reqid_2to1} "
            )
            + iptfs_opts
        )

        # repl.cmd_raises(f"ip add vti0 local {lip} remote {rip} mode vti key 55")
        # repl.cmd_raises("sysctl -w net.ipv4.conf.vti0.disable_policy=1")
        # repl.cmd_raises("ip link set vti0 up")

        if r == r1 or not network3:
            ipsec_net = "net1"
        else:
            ipsec_net = "net2"

        if ipsec_net in r.net_intfs:
            repl.cmd_raises(
                f"ip link add ipsec0 type xfrm dev {r.net_intfs[ipsec_net]} if_id 55"
            )
        else:
            repl.cmd_raises(f"ip link add ipsec0 type xfrm dev {ipsec_intf} if_id 55")

        # repl.cmd_raises("sysctl -w net.ipv4.conf.ipsec0.disable_policy=1")
        # repl.cmd_raises("ip link set ipsec0 mtu 65536 up")
        repl.cmd_raises("ip link set ipsec0 up")

        #
        # Policy
        #
        xdef = "0.0.0.0/0"
        direction = "dir out"
        repl.cmd_raises(
            f"ip xfrm policy add if_id 55 src {xdef} dst {xdef} {direction}"
            f" tmpl src {lip} dst {rip} proto esp mode {mode} reqid {oreqid}"
        )

        for direction in ["dir fwd", "dir in"]:
            repl.cmd_raises(
                f"ip xfrm policy add if_id 55 src {xdef} dst {xdef} {direction} "
                f"tmpl src {rip} dst {lip} proto esp mode {mode} reqid {ireqid}"
            )

        #
        # Policy
        #
        xdef = "::/0"
        direction = "dir out"
        repl.cmd_raises(
            f"ip -6 xfrm policy add if_id 55 src {xdef} dst {xdef} {direction}"
            f" tmpl src {lip} dst {rip} proto esp mode {mode} reqid {oreqid}"
        )

        for direction in ["dir fwd", "dir in"]:
            repl.cmd_raises(
                f"ip -6 xfrm policy add if_id 55 src {xdef} dst {xdef} {direction} "
                f"tmpl src {rip} dst {lip} proto esp mode {mode} reqid {ireqid}"
            )

    r1con = r1.conrepl if r1 else None
    r2con = r2.conrepl if r2 and not r1only else None

    setup_tunnel_routes(r1con, r2con, tun_ipv6, network3)

    mtustr = f"mtu {tun_route_mtu}" if tun_route_mtu else ""

    r1srcip = f"src 10.0.1.2 {mtustr}"
    r1srcip6 = f"src fc00:0:0:0::2 {mtustr}"
    if network3:
        r2srcip = f"src 10.0.3.4 {mtustr}"
        r2srcip6 = f"src fc00:0:0:3::4 {mtustr}"
    else:
        r2srcip = f"src 10.0.2.3 {mtustr}"
        r2srcip6 = f"src fc00:0:0:2::3 {mtustr}"

    #
    # Setup inner traffic routes
    #
    if ipv4:
        if not trex:
            if r1con:
                r1con.cmd_raises(f"ip route add 10.0.2.0/24 dev ipsec0 {r1srcip}")
                if network3:
                    r1con.cmd_raises(f"ip route add 10.0.3.0/24 dev ipsec0 {r1srcip}")
            if r2con:
                r2con.cmd_raises(f"ip route add 10.0.0.0/24 dev ipsec0 {r2srcip}")
                if network3:
                    r2con.cmd_raises(f"ip route add 10.0.1.0/24 dev ipsec0 {r2srcip}")

        else:
            if r1con:
                r1con.cmd_raises(f"ip route add 12.0.0.0/24 dev ipsec0 {r1srcip}")
                r1con.cmd_raises(f"ip route add 48.0.0.0/8 dev ipsec0 {r1srcip}")

            if r2con:
                r2con.cmd_raises(f"ip route add 11.0.0.0/24 dev ipsec0 {r2srcip}")
                r2con.cmd_raises(f"ip route add 16.0.0.0/8 dev ipsec0 {r2srcip}")

    if ipv6:
        if not trex:
            if r1con:
                r1con.cmd_raises(f"ip route add fc00:0:0:2::/64 dev ipsec0 {r1srcip6}")
                if network3:
                    r1con.cmd_raises(
                        f"ip route add fc00:0:0:3::/64 dev ipsec0 {r1srcip6}"
                    )
            if r2con:
                r2con.cmd_raises(f"ip route add fc00:0:0:0::/64 dev ipsec0 {r2srcip6}")
                if network3:
                    r2con.cmd_raises(
                        f"ip route add fc00:0:0:1::/64 dev ipsec0 {r2srcip6}"
                    )
        else:
            if r1con:
                r1con.cmd_raises(f"ip route add 2012::/64 dev ipsec0 {r1srcip6}")
                r1con.cmd_raises(f"ip route add 2048::/16 dev ipsec0 {r1srcip6}")
            if r2con:
                r2con.cmd_raises(f"ip route add 2011::/64 dev ipsec0 {r2srcip6}")
                r2con.cmd_raises(f"ip route add 2016::/16 dev ipsec0 {r2srcip6}")


def create_scapy_sa_pair(
    mode="iptfs",
    use_gcm=True,
    use_nullnull=False,
    enc_null=False,
    mtu=1500,
    addr1="10.0.1.2",
    addr2="10.0.1.3",
    seq_num1=0,
    seq_num2=0,
    tun_ipv6=False,
):
    from scapy.layers import ipsec
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6

    if ipaddress.ip_address(addr1).version == 4:
        ipcls = IP
    else:
        ipcls = IPv6

    linux_algo_to_scapy = {
        "rfc4106(gcm(aes))": "AES-GCM",
        "seqiv(rfc4106(gcm(aes)))": "AES-GCM",
        "cipher_null": "NULL",
        "cbc(aes)": "AES-CBC",
        "hmac(sha1)": "HMAC-SHA1-96",
    }

    def key_str_to_bytes(es):
        if es.startswith("0x"):
            es = es[2:]
        return binascii.unhexlify(es)

    spi_1to2, spi_2to1, sa_auth, sa_enc = get_sa_values(
        use_gcm, use_nullnull, enc_null, tun_ipv6=tun_ipv6
    )
    sa_auth = shlex.split(sa_auth)
    sa_enc = shlex.split(sa_enc)

    kwargs = {
        "auth_key": key_str_to_bytes(sa_auth[2]) if sa_auth else "",
        "auth_algo": linux_algo_to_scapy[sa_auth[1]] if sa_auth else None,
        "crypt_key": key_str_to_bytes(sa_enc[2]),
        "crypt_algo": linux_algo_to_scapy[sa_enc[1]],
    }
    if mode == "iptfs":
        SA = iptfs.SecurityAssociation
        kwargs["mtu"] = mtu
    else:
        SA = ipsec.SecurityAssociation

    ip1 = ipcls(src=addr1, dst=addr2)
    ip2 = ipcls(src=addr2, dst=addr1)
    sa_1to2 = SA(ipsec.ESP, spi_1to2, tunnel_header=ip1, seq_num=seq_num1, **kwargs)
    sa_2to1 = SA(ipsec.ESP, spi_2to1, tunnel_header=ip2, seq_num=seq_num2, **kwargs)

    return sa_1to2, sa_2to1
