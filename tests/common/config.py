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


async def _network_up(unet, r1only=False):
    h1 = unet.hosts["h1"] if "h1" in unet.hosts else None
    h2 = unet.hosts["h2"] if "h2" in unet.hosts else None
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"] if not r1only else None

    await toggle_ipv6(unet, enable=False)

    if h1:
        h1.cmd_raises("ip route add 10.0.2.0/24 via 10.0.0.2")
        h1.cmd_raises("ip route add 10.0.1.0/24 via 10.0.0.2")

    r1.conrepl.cmd_raises("ip route add 10.0.2.0/24 via 10.0.1.3")

    if r2:
        r2.conrepl.cmd_raises("ip route add 10.0.0.0/24 via 10.0.1.2")

    if h2:
        h2.cmd_raises("ip route add 10.0.1.0/24 via 10.0.2.3")
        h2.cmd_raises("ip route add 10.0.0.0/24 via 10.0.2.3")


async def cleanup_config(unet, r1only=False):
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]

    r1.conrepl.cmd_nostatus(f"ip link del ipsec0")
    if not r1only:
        r2.conrepl.cmd_nostatus(f"ip link del ipsec0")

    r1.conrepl.cmd_nostatus("ip route del 10.0.2.0/24 dev ipsec0")
    r1.conrepl.cmd_nostatus("ip route del 12.0.0.0/24 dev ipsec0")
    r1.conrepl.cmd_nostatus("ip route del 48.0.0.0/8 dev ipsec0")

    if not r1only:
        r2.conrepl.cmd_nostatus("ip route del 10.0.0.0/24 dev ipsec0")
        r2.conrepl.cmd_nostatus("ip route del 11.0.0.0/24 dev ipsec0")
        r2.conrepl.cmd_nostatus("ip route del 16.0.0.0/8 dev ipsec0")

    r1.conrepl.cmd_nostatus("ip route del 10.0.2.0/24 via 10.0.1.3")
    r1.conrepl.cmd_nostatus("ip route del 12.0.0.0/24 via 10.0.1.3")
    r1.conrepl.cmd_nostatus("ip route del 48.0.0.0/8 via 10.0.1.3")

    if not r1only:
        r2.conrepl.cmd_nostatus("ip route del 10.0.0.0/24 via 10.0.1.2")
        r2.conrepl.cmd_nostatus("ip route del 11.0.0.0/24 via 10.0.1.2")
        r2.conrepl.cmd_nostatus("ip route del 16.0.0.0/8 via 10.0.1.2")

    r1.conrepl.cmd_nostatus("ip x s deleteall")
    r1.conrepl.cmd_nostatus("ip x p deleteall")

    if not r1only:
        r2.conrepl.cmd_nostatus("ip x s deleteall")
        r2.conrepl.cmd_nostatus("ip x p deleteall")


async def toggle_ipv6(unet, enable=False):
    for node in unet.hosts.values():
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


def get_sa_values(use_gcm=True, use_nullnull=False, enc_null=False):
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
            "0x4a506a794f574265564551694d6537681A2B1A2B "
            "128"
            # "0x4a506a794f574265564551694d6537684a"
            # "506a794f574265564551694d6537681A2B1A2B "
            # "256"
        )
    elif enc_null:
        spi_1to2 = 0xAAAA
        spi_2to1 = 0xBBBB
        sa_auth = "auth sha256 0x0123456789ABCDEF0123456789ABCDEF"
        sa_enc = 'enc cipher_null ""'
    else:
        spi_1to2 = 0xAA
        spi_2to1 = 0xBB
        sa_auth = "auth sha256 0x0123456789ABCDEF0123456789ABCDEF"
        sa_enc = "enc aes 0xFEDCBA9876543210FEDCBA9876543210"
    return spi_1to2, spi_2to1, sa_auth, sa_enc


async def setup_policy_tun(
    unet,
    mode="iptfs",
    use_gcm=True,
    use_nullnull=False,
    enc_null=False,
    trex=False,
    r1only=False,
    ipsec_intf="eth2",
):
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]

    reqid_1to2 = 0x10
    reqid_2to1 = 0x11

    spi_1to2, spi_2to1, sa_auth, sa_enc = get_sa_values(use_gcm, use_nullnull, enc_null)

    r1ipp = r1.intf_addrs[ipsec_intf]
    r1ip = r1ipp.ip
    r1ipp = r1ipp.network
    r2ipp = r2.intf_addrs[ipsec_intf]
    r2ip = r2ipp.ip
    r2ipp = r2ipp.network

    # Start with a clean slate
    await cleanup_config(unet, r1only=r1only)

    for r in (r1, r2) if not r1only else (r1,):
        repl = r.conrepl
        #
        # SAs
        #
        repl.cmd_raises(
            f"ip xfrm state add src {r1ip} dst {r2ip} proto esp "
            f"spi {spi_1to2} mode {mode} {sa_auth} {sa_enc} "
            f"reqid {reqid_1to2}"
        )
        repl.cmd_raises(
            f"ip xfrm state add src {r2ip} dst {r1ip} proto esp "
            f"spi {spi_2to1} mode {mode} {sa_auth} {sa_enc} "
            f"reqid {reqid_2to1}"
        )

        #
        # Policy
        #
        if not trex:
            iplist = [
                ("10.0.0.0/24", "10.0.1.0/24"),  # host to router
                ("10.0.1.0/24", "10.0.1.0/24"),  # router to router
                ("10.0.1.0/24", "10.0.2.0/24"),  # host to router
                ("10.0.0.0/24", "10.0.2.0/24"),  # host to host
            ]
        else:
            iplist = [
                ("10.0.1.0/24", "10.0.1.0/24"),  # router to router
                ("11.0.0.0/24", "12.0.0.0/24"),  # host to host
                ("16.0.0.0/8", "48.0.0.0/8"),  # host to host
            ]

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

    if not trex:
        r1.conrepl.cmd_raises("ip route add 10.0.2.0/24 via 10.0.1.3")
        if not r1only:
            r2.conrepl.cmd_raises("ip route add 10.0.0.0/24 via 10.0.1.2")
    else:
        r1.conrepl.cmd_raises("ip route add 12.0.0.0/24 via 10.0.1.3")
        r1.conrepl.cmd_raises("ip route add 48.0.0.0/8 via 10.0.1.3")

        if not r1only:
            r2.conrepl.cmd_raises("ip route add 11.0.0.0/24 via 10.0.1.2")
            r2.conrepl.cmd_raises("ip route add 16.0.0.0/8 via 10.0.1.2")


async def setup_routed_tun(
    unet,
    mode="iptfs",
    use_gcm=True,
    use_nullnull=False,
    enc_null=False,
    trex=False,
    r1only=False,
    ipsec_intf="eth2",
):
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]

    reqid_1to2 = 8
    reqid_2to1 = 9

    spi_1to2, spi_2to1, sa_auth, sa_enc = get_sa_values(use_gcm, use_nullnull, enc_null)

    r1ipp = r1.intf_addrs[ipsec_intf]
    r1ip = r1ipp.ip
    r1ipp = r1ipp.network
    r2ipp = r2.intf_addrs[ipsec_intf]
    r2ip = r2ipp.ip
    r2ipp = r2ipp.network

    # Start with a clean slate
    await cleanup_config(unet, r1only=r1only)

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
            f"ip xfrm state add src {r1ip} dst {r2ip} proto esp "
            f"spi {spi_1to2} mode {mode} {sa_auth} {sa_enc} "
            f"if_id 55 reqid {reqid_1to2}"
        )
        repl.cmd_raises(
            f"ip xfrm state add src {r2ip} dst {r1ip} proto esp "
            f"spi {spi_2to1} mode {mode} {sa_auth} {sa_enc} "
            f"if_id 55 reqid {reqid_2to1}"
        )

        # repl.cmd_raises(f"ip add vti0 local {lip} remote {rip} mode vti key 55")
        # repl.cmd_raises("sysctl -w net.ipv4.conf.vti0.disable_policy=1")
        # repl.cmd_raises("ip link set vti0 up")
        if "net1" in r.net_intfs:
            repl.cmd_raises(
                f"ip link add ipsec0 type xfrm dev {r.net_intfs['net1']} if_id 55"
            )
        else:
            repl.cmd_raises(f"ip link add ipsec0 type xfrm dev {ipsec_intf} if_id 55")
        # repl.cmd_raises("sysctl -w net.ipv4.conf.ipsec0.disable_policy=1")
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

    if not trex:
        # Add ipsec0 based routes
        r1.conrepl.cmd_raises("ip route add 10.0.2.0/24 dev ipsec0 src 10.0.1.2")
        if not r1only:
            r2.conrepl.cmd_raises("ip route add 10.0.0.0/24 dev ipsec0 src 10.0.1.3")
    else:
        # trex direct remote routes
        r1.conrepl.cmd_raises("ip route add 12.0.0.0/24 dev ipsec0 src 10.0.1.2")
        if not r1only:
            r2.conrepl.cmd_raises("ip route add 11.0.0.0/24 dev ipsec0 src 10.0.1.3")

        # trex indirect remote routes
        r1.conrepl.cmd_raises("ip route add 48.0.0.0/8 dev ipsec0 src 10.0.1.2")
        if not r1only:
            r2.conrepl.cmd_raises("ip route add 16.0.0.0/8 dev ipsec0 src 10.0.1.3")
