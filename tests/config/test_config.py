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
"Simple virtual interface qemu based iptfs test."
import logging
import os
import re

import pytest
from common.config import _network_up, setup_routed_tun
from common.tests import _test_net_up

# All tests are coroutines
pytestmark = pytest.mark.asyncio

SRCDIR = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module", autouse=True)
async def network_up(unet):
    await _network_up(unet)


#                             192.168.0.0/24
#   --+-------------------+------ mgmt0 ------+-------------------+---
#     | .1                | .2                | .3                | .4
#   +----+              +----+              +----+              +----+
#   | h1 | --- net0 --- | r1 | --- net1 --- | r2 | --- net2 --- | r1 |
#   +----+ .1        .2 +----+ .2        .3 +----+ .3        .4 +----+
#          10.0.0.0/24         10.0.1.0/24         10.0.2.0/24


async def test_net_up(unet):
    await _test_net_up(unet)


@pytest.mark.parametrize("df", ["", "dont-frag"])
@pytest.mark.parametrize("psize", ["", "pkt-size 0", "pkt-size 1000"])
@pytest.mark.parametrize("qsize", ["", "max-queue-size 10240"])
@pytest.mark.parametrize("idelay", ["", "init-delay 50000"])
@pytest.mark.parametrize("rewin", ["", "reorder-window 5"])
@pytest.mark.parametrize("dtime", ["", "drop-time 100000"])
async def test_config_combo(unet, astepf, psize, qsize, dtime, rewin, idelay, df):
    h1 = unet.hosts["h1"]
    r1 = unet.hosts["r1"]

    args = (x for x in [psize, qsize, dtime, rewin, idelay, df] if x)
    args = " ".join(args)

    await astepf("before setup: args: " + args)
    await setup_routed_tun(unet, iptfs_opts=args)

    await astepf("before ping")
    output = h1.cmd_raises("ping -c1 10.0.2.4")

    if not os.environ.get("CI"):
        # Measure the delay
        m = re.search(r"time=(\d+(.\d+)?) ms", output)
        # The CI test is experiencing 40ms RTT.. really horrible
        if idelay:
            assert 99 < float(m.group(1)) < 160.0
        else:
            assert 0 < float(m.group(1)) < 30.0

    # # we can only test don't fragment with pkt-size
    # if psize:
    #     if df:
    #         rc, _, _ = h1.cmd_status("ping -M do -s 1000 -c1 10.0.2.4")
    #         assert rc != 0, "dont-frag but still worked"
    #     # else:
    #     #     h1.cmd_raises("ping -M do -s 1000 -c1 10.0.2.4")

    output = r1.conrepl.cmd_raises("ip x s l")
    logging.debug(output)

    if df:
        assert "dont-frag" in output
    else:
        assert "dont-frag" not in output

    if psize:
        assert psize in output
    else:
        assert "pkt-size 0" in output

    if qsize:
        assert qsize in output
    else:
        assert "max-queue-size 1048576" in output

    if idelay:
        assert idelay in output
    else:
        assert "init-delay 0" in output

    if rewin:
        assert rewin in output
    else:
        assert "reorder-window 3" in output

    if dtime:
        assert dtime in output
    else:
        assert "drop-time 1000000" in output


async def test_config_sysctl(unet):
    r1 = unet.hosts["r1"]

    r1.conrepl.cmd_raises("sysctl -w net.core.xfrm_iptfs_drptime=50000")
    r1.conrepl.cmd_raises("sysctl -w net.core.xfrm_iptfs_idelay=1000")
    r1.conrepl.cmd_raises("sysctl -w net.core.xfrm_iptfs_maxqsize=500000")
    r1.conrepl.cmd_raises("sysctl -w net.core.xfrm_iptfs_rewin=1")

    await setup_routed_tun(unet)

    output = r1.conrepl.cmd_raises("ip x s l")
    logging.debug(output)
    assert "max-queue-size 500000" in output
    assert "init-delay 1000" in output
    assert "reorder-window 1" in output
    assert "drop-time 50000" in output
