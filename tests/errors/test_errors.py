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
import time

import pytest

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
    repl = await rtr.console(
        cmd, user="root", password="root", use_pty=False, trace=True
    )
    repl.cmd_status("set +o emacs")
    return repl


@pytest.fixture(scope="module", name="r1repl")
async def r1repl_(unet):
    return await console(unet, unet.hosts["r1"])


@pytest.fixture(scope="module", name="r2repl")
async def r2repl_(unet):
    return await console(unet, unet.hosts["r2"])


@pytest.fixture(scope="module", autouse=True)
async def network_up(unet, r1repl, r2repl):
    h1 = unet.hosts["h1"]
    h2 = unet.hosts["h2"]
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]
    for r, repl in [(r1, r1repl), (r2, r2repl)]:
        repl.cmd_raises("sysctl -w net.ipv4.ip_forward=1")
        repl.cmd_raises("ip link set lo up")

        for i in range(0, 3):
            repl.cmd_raises(f"ip link set eth{i} up")
            repl.cmd_raises(f"ip addr add {r.intf_addrs[f'eth{i}']} dev eth{i}")

    h1.cmd_raises("ip route add 10.0.2.0/24 via 10.0.0.2")
    h1.cmd_raises("ip route add 10.0.1.0/24 via 10.0.0.2")

    r1repl.cmd_raises("ip route add 10.0.2.0/24 via 10.0.1.3")
    r2repl.cmd_raises("ip route add 10.0.0.0/24 via 10.0.1.2")

    h1.cmd_raises("ip link set eth1 mtu 9000")
    r1repl.cmd_raises("ip link set eth1 mtu 9000")
    r1repl.cmd_raises("ip link set eth2 mtu 9000")
    r2repl.cmd_raises("ip link set eth1 mtu 9000")
    r2repl.cmd_raises("ip link set eth2 mtu 9000")
    h2.cmd_raises("ip link set eth1 mtu 9000")

    # Lower the host side interface MTU to 750
    r2repl.cmd_raises("ip link set eth1 mtu 800")
    h2.cmd_raises("ip link set eth1 mtu 800")

    h2.cmd_raises("ip route add 10.0.1.0/24 via 10.0.2.3")
    h2.cmd_raises("ip route add 10.0.0.0/24 via 10.0.2.3")


#                             192.168.0.0/24
#   --+-------------------+------ mgmt0 ------+-------------------+---
#     | .1                | .2                | .3                | .4
#   +----+              +----+              +----+              +----+
#   | h1 | --- net0 --- | r1 | --- net1 --- | r2 | --- net2 --- | r1 |
#   +----+ .1        .2 +----+ .2        .3 +----+ .3        .4 +----+
#          10.0.0.0/24         10.0.1.0/24         10.0.2.0/24


async def test_net_up(unet, r1repl):
    # pings mgmt0 bridge
    logging.info(unet.hosts["h1"].cmd_raises("ping -w1 -i.2 -c1 192.168.0.254"))
    # h1 pings r1 (qemu side)
    logging.info(unet.hosts["h1"].cmd_raises("ping -w1 -i.2 -c1 10.0.0.2"))
    # h1 pings r1 (namespace side)
    logging.info(unet.hosts["h1"].cmd_raises("ping -w1 -i.2 -c1 10.0.0.202"))
    # h1 pings r1 (other side)
    logging.info(unet.hosts["h1"].cmd_raises("ping -w1 -i.2 -c1 10.0.1.2"))
    # h1 pings r2
    logging.info(unet.hosts["h1"].cmd_raises("ping -w1 -i.2 -c1 10.0.1.3"))
    # h1 pings h2
    logging.info(unet.hosts["h1"].cmd_raises("ping -w1 -i.2 -c1 10.0.2.4"))

    # r1 (qemu side) pings mgmt0 brige
    logging.info(r1repl.cmd_raises("ping -w1 -i.2 -c1 192.168.0.254"))
    # r1 (qemu side) pings h1
    logging.info(r1repl.cmd_raises("ping -w1 -i.2 -c1 10.0.0.1"))
    # logging.info(r1repl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.2"))
    # r1 (qemu side) pings r1 (namespace side)
    logging.info(r1repl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.202"))
    # r1 (qemu side) pings r2 (qemu side)
    logging.info(r1repl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.3"))
    # r1 (qemu side) pings r2 (namespace side)
    logging.info(r1repl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.203"))

    # # r2 (qemu side) pings all mgmt0
    # logging.info(r2repl.cmd_raises("ping -w1 -i.2 -c1 192.168.0.254"))
    # logging.info(r2repl.cmd_raises("ping -w1 -i.2 -c1 192.168.0.202"))
    # logging.info(r2repl.cmd_raises("ping -w1 -i.2 -c1 192.168.0.203"))
    # logging.info(r2repl.cmd_raises("ping -w1 -i.2 -c1 192.168.0.1"))
    # logging.info(r2repl.cmd_raises("ping -w1 -i.2 -c1 192.168.0.2"))
    # logging.info(r2repl.cmd_raises("ping -w1 -i.2 -c1 192.168.0.3"))
    # logging.info(r2repl.cmd_raises("ping -w1 -i.2 -c1 192.168.0.4"))

    # # r2 (qemu side) pings r1 (qemu side)
    # logging.info(r2repl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.2"))
    # # r2 (qemu side) pings r1 (namespace side)
    # logging.info(r2repl.cmd_raises("ping -w1 -i.2 -c1 10.0.1.202"))
    # # logging.info(r2repl.cmd_raises("ping -w1 -i.2 -c1 10.0.2.3"))
    # # r2 (qemu side) pings r2 (namespace side)
    # logging.info(r2repl.cmd_raises("ping -w1 -i.2 -c1 10.0.2.203"))
    # # r2 (qemu side) pings h2
    # logging.info(r2repl.cmd_raises("ping -w1 -i.2 -c1 10.0.2.4"))

    # h2 pings mgmt0 bridge
    logging.info(unet.hosts["h2"].cmd_raises("ping -w1 -i.2 -c1 192.168.0.254"))
    # h2 pings r2 (qemu side)
    logging.info(unet.hosts["h2"].cmd_raises("ping -w1 -i.2 -c1 10.0.2.3"))
    # h2 pings r2 (namespace side)
    logging.info(unet.hosts["h2"].cmd_raises("ping -w1 -i.2 -c1 10.0.2.203"))
    # h2 pings r2 (other side)
    logging.info(unet.hosts["h2"].cmd_raises("ping -w1 -i.2 -c1 10.0.1.3"))
    # h2 pings r1
    logging.info(unet.hosts["h2"].cmd_raises("ping -w1 -i.2 -c1 10.0.1.2"))
    # h2 pings h1
    logging.info(unet.hosts["h2"].cmd_raises("ping -w1 -i.2 -c1 10.0.0.1"))


USE_GCM = True
USE_NULLNULL = False


async def test_policy_mtu(unet, r1repl, r2repl, astepf):
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]
    h1 = unet.hosts["h1"]

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

    r1ipp = r1.intf_addrs["eth2"]
    r1ip = r1ipp.ip
    r1ipp = r1ipp.network

    r2ipp = r2.intf_addrs["eth2"]
    r2ip = r2ipp.ip
    r2ipp = r2ipp.network

    for r, repl in [(r1, r1repl), (r2, r2repl)]:
        #
        # SAs
        #
        repl.cmd_raises(
            f"ip xfrm state add src {r1ip} dst {r2ip} proto esp "
            f"spi {rspi} mode tunnel {sa_auth} {sa_enc} "
            f"reqid 0x10"
        )
        repl.cmd_raises(
            f"ip xfrm state add src {r2ip} dst {r1ip} proto esp "
            f"spi {lspi} mode tunnel {sa_auth} {sa_enc} "
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
                    f"tmpl src {r1ip} dst {r2ip} proto esp mode tunnel "
                    f"reqid 0x10",
                    # " spi {rspi} "
                )
            for direction in ["dir out"] if r == r2 else ["dir fwd", "dir in"]:
                repl.cmd_raises(
                    f"ip xfrm policy add src {x2ipp} dst {x1ipp} {direction} "
                    f"tmpl src {r2ip} dst {r1ip} proto esp mode tunnel "
                    f"reqid 0x11",
                    # " spi {lspi} "
                )

    await astepf("Send initial small ping")
    logging.info(h1.cmd_raises("ping -c1 10.0.2.4"))

    await astepf("Send too big ping")
    logging.info(h1.cmd_raises("ping -s 1000 -Mdo -c1 10.0.2.4"))

    await astepf("Test complete")


async def test_iptfs_mtu(unet, r1repl, r2repl, astepf):
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]
    h1 = unet.hosts["h1"]

    if not USE_GCM:
        if USE_NULLNULL:
            rspi = 0xAAAAAA
            lspi = 0xBBBBBB
            sa_auth = 'auth digest_null ""'
            sa_enc = 'enc cipher_null ""'
        else:
            rspi = 0xAAAA
            lspi = 0xBBBB
            sa_auth = "auth sha1 0x4339314b55523947594d6d3547666b45764e6a58"
            # sa_auth = "auth sha256 0x0123456789ABCDEF0123456789ABCDEF"
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

    r1ipp = r1.intf_addrs["eth2"]
    r1ip = r1ipp.ip
    r1ipp = r1ipp.network

    r2ipp = r2.intf_addrs["eth2"]
    r2ip = r2ipp.ip
    r2ipp = r2ipp.network

    for r, repl in [(r1, r1repl), (r2, r2repl)]:
        #
        # SAs
        #
        repl.cmd_raises(
            f"ip xfrm state add src {r1ip} dst {r2ip} proto esp "
            f"spi {rspi} mode iptfs {sa_auth} {sa_enc} "
            f"reqid 0x10"
        )
        repl.cmd_raises(
            f"ip xfrm state add src {r2ip} dst {r1ip} proto esp "
            f"spi {lspi} mode iptfs {sa_auth} {sa_enc} "
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
                    f"tmpl src {r1ip} dst {r2ip} proto esp mode iptfs "
                    f"reqid 0x10",
                    # " spi {rspi} "
                )
            for direction in ["dir out"] if r == r2 else ["dir fwd", "dir in"]:
                repl.cmd_raises(
                    f"ip xfrm policy add src {x2ipp} dst {x1ipp} {direction} "
                    f"tmpl src {r2ip} dst {r1ip} proto esp mode iptfs "
                    f"reqid 0x11",
                    # " spi {lspi} "
                )

    await astepf("Send initial small ping")
    logging.info(h1.cmd_raises("ping -c1 10.0.2.4"))

    await astepf("Send too big ping")
    logging.info(h1.cmd_raises("ping -s 1000 -Mdo -c1 10.0.2.4"))

    await astepf("Test complete")
