# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# January 19 2023, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2023, LabN Consulting, L.L.C.
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
"Test iptfs tunnel using iperf with various configurations"
import os

import pytest
from common.config import _network_up, cleanup_config
from common.tests import _test_net_up
from iperf import _test_iperf, check_logs, skip_future
from munet.testing.fixtures import _unet_impl

# All tests are coroutines
pytestmark = pytest.mark.asyncio

SRCDIR = os.path.dirname(os.path.abspath(__file__))

MODE = "iptfs"


# When leaks happen there are 2 leaks pared up:
#
# unreferenced object 0xffff888104f41000 (size 256):
#   comm "softirq", pid 0, jiffies 4294675993 (age 679.156s)
#   hex dump (first 32 bytes):
#     00 00 00 00 00 00 00 00 60 3a 00 00 00 c9 ff ff  ........`:......
#     00 a0 d2 03 81 88 ff ff 00 00 00 00 00 00 00 00  ................
#   backtrace:
#     [<00000000870c9727>] kmem_cache_alloc+0x164/0x290
#     [<00000000e6f3186a>] build_skb+0x29/0xe0
#     [<00000000021a22e7>] page_to_skb+0xa1/0x5c0
#     [<00000000cd01171f>] receive_buf+0x596/0x1a90
#     [<000000008ec2992e>] virtnet_poll+0x211/0x590
#     [<000000001e9d3881>] __napi_poll+0x2e/0x1d0
#     [<00000000d7e4cf66>] net_rx_action+0x289/0x300
#     [<00000000a90cd6f6>] __do_softirq+0xc5/0x299
# unreferenced object 0xffff88810556c900 (size 128):
#   comm "softirq", pid 0, jiffies 4294675993 (age 679.156s)
#   hex dump (first 32 bytes):
#     01 00 00 00 01 0b 00 00 01 00 00 00 00 00 00 00  ................
#     00 c0 55 05 81 88 ff ff 00 00 00 00 00 00 00 00  ..U.............
#   backtrace:
#     [<00000000870c9727>] kmem_cache_alloc+0x164/0x290
#     [<00000000a5bec97c>] skb_ext_add+0x109/0x1e0
#     [<00000000afcd5e7b>] secpath_set+0x6c/0x80
#     [<000000005ff45f44>] xfrm_input+0x233/0x1380
#     [<00000000266d293c>] xfrmi4_rcv+0x6a/0xa0
#     [<00000000a28f221f>] xfrm4_esp_rcv+0x2f/0x80
#     [<00000000439022c5>] ip_protocol_deliver_rcu+0x175/0x180
#     [<000000002c5b0086>] ip_local_deliver_finish+0x8a/0xb0
#     [<00000000f762997e>] ip_local_deliver+0x73/0x120
#     [<000000002b7ac9a3>] ip_sublist_rcv_finish+0x6b/0x80
#     [<00000000bd4e9dbb>] ip_sublist_rcv+0x116/0x1b0
#     [<00000000bc684f7f>] ip_list_rcv+0xfd/0x130
#     [<00000000884dbce6>] __netif_receive_skb_list_core+0x218/0x240
#     [<00000000ce3b3b77>] netif_receive_skb_list_internal+0x18f/0x2b0
#     [<0000000086d9c1fa>] napi_complete_done+0x7e/0x1c0
#     [<00000000780ac000>] virtnet_poll+0x408/0x590


@pytest.fixture(scope="module", name="unet")
async def _unet(rundir_module, pytestconfig):
    async for x in _unet_impl(rundir_module, pytestconfig):
        await _network_up(x, ipv6=True)
        x.hosts["r1"].add_watch_log("qemu.out")
        x.hosts["r2"].add_watch_log("qemu.out")
        yield x

    # try:
    #     print("XXX adding watch task")
    #     task = unet.hosts["r1"].add_watch_log("qemu.out", "(Kernel panic|BUG:|Oops:) ")
    #     tasks.append(task)
    #     print("XXX adding watch task")
    #     task = unet.hosts["r2"].add_watch_log("qemu.out", "(Kernel panic|BUG:|Oops:) ")
    #     tasks.append(task)

    #     print("XXX yielding")
    #     yield
    #     print("XXX back from yield")
    # finally:
    #     for task in tasks:
    #         task.cancel()


#                       192.168.0.0/24  fd00::/64
#   --+-------------------+------ mgmt0 ------+-------------------+---
#     | .1                | .2                | .3                | .4
#   +----+              +----+              +----+              +----+
#   | h1 | --- net0 --- | r1 | --- net1 --- | r2 | --- net2 --- | r1 |
#   +----+ .1        .2 +----+ .2        .3 +----+ .3        .4 +----+
#          10.0.0.0/24         10.0.1.0/24         10.0.2.0/24


# async def test_net_up(unet):
#     await _test_net_up(unet, ipv6=True)
#     check_logs(unet)


# @pytest.mark.parametrize("pktsize", [None, 64, 536, 1442])

# Leaks only with no dont-frag
# IPv4 tunnel with IPv4 inner, Fails start at 1403  -- 1442 - 1402 ==  40 works 1403 == 39 doesn't
# @pytest.mark.parametrize("pktsize", [1400, 1401, 1402, 1403, 1404, 1405])
# IPv6 tunnel with IPv4 inner or vice versa, fails start at 1383
# @pytest.mark.parametrize("pktsize", [1380, 1381, 1382, 1383, 1384, 1385, 1386])
# IPv6 Tunnel with IPv6 inner fails start at 1363
# @pytest.mark.parametrize("pktsize", [1360, 1361, 1362, 1363, 1364, 1365])
# [    4.504257] INGRESS: LINEARIZE skb->len=2956 skb->data_len=2916 skb->nr_frags=1 skb->frag_list=0000000000000000
# pktsize == 2916 works, 2917+ doesn't


# @pytest.mark.parametrize("iptfs_opts", ["init-delay 500"], scope="function")
# @pytest.mark.parametrize("pktsize", [None, 88, 536, 8000])
# @pytest.mark.parametrize("ipv6", [False, True])
# @pytest.mark.parametrize("tun_ipv6", [False, True])
# @pytest.mark.parametrize("routed", [False, True])

# @pytest.mark.parametrize(
#     "iptfs_opts", ["pkt-size 256 max-queue-size 100000"], scope="function"
# )


@pytest.mark.parametrize("iptfs_opts", [""], scope="function")
@pytest.mark.parametrize("pktsize", [None, 88, 536, 1442])
@pytest.mark.parametrize("ipv6", [False, True])
@pytest.mark.parametrize("tun_ipv6", [False, True])
@pytest.mark.parametrize("routed", [False, True])
async def test_iperf(
    unet, astepf, pytestconfig, iptfs_opts, pktsize, ipv6, routed, tun_ipv6
):
    if skip_future:
        pytest.skip("Skipping test due to earlier failure")

    unet.hosts["r1"].cmd_nostatus(
        f"echo test start: routed={routed} v6tun={tun_ipv6} v6={ipv6} pktsize={pktsize} opts={iptfs_opts} > /dev/kmsg"
    )
    unet.hosts["r2"].cmd_nostatus(
        f"echo test start: routed={routed} v6tun={tun_ipv6} v6={ipv6} pktsize={pktsize} opts={iptfs_opts} > /dev/kmsg"
    )

    await cleanup_config(unet, ipv4=True, ipv6=True)
    await _test_net_up(unet, ipv6=True, multihop=False)
    check_logs(unet)

    if not unet.ipv6_enable and tun_ipv6:
        pytest.skip("skipping ipv6 as --enable-ipv6 not specified")

    if tun_ipv6 and pktsize and pktsize < 536:
        pytest.skip("Can't run IPv6 iperf with MSS < 536")
        return

    if tun_ipv6 and pktsize and pktsize == 1442:
        pktsize = 1428

    test_iperf.count += 1

    use_iperf3 = True
    if use_iperf3 and pktsize and pktsize < 88:
        pktsize = 88

    result = await _test_iperf(
        unet,
        astepf,
        mode=MODE,
        ipsec_intf="eth2",
        use_iperf3=use_iperf3,
        iptfs_opts=iptfs_opts,
        pktsize=pktsize,
        routed=routed,
        ipv6=ipv6,
        tun_ipv6=tun_ipv6,
        profile=pytestconfig.getoption("--profile", False),
        profcount=test_iperf.count,
        tracing=pytestconfig.getoption("--tracing", False),
        duration=pytestconfig.getoption("--duration", 10.0),
    )
    assert result, "No result from test!"

    rundir = str(unet.rundir)
    fname = rundir[: rundir.rindex("/")] + "/speed.csv"
    fmode = "w+" if test_iperf.count == 0 else "a+"
    tunstr = "routed" if routed else "policy"
    vstr = "IPv6" if tun_ipv6 else "IPv4"
    with open(fname, fmode, encoding="ascii") as f:
        print(
            f"{result[2]}{result[3]}bits/s,{result[1]},{result[0]},{pktsize},{tunstr},{vstr},{iptfs_opts}",
            file=f,
        )


test_iperf.count = -1
