# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# August 15 2023, Christian Hopps <chopps@labn.net>
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
"Test IKE using strongswan"
import logging
import os
from pathlib import Path

import pytest
from common.config import _network_up
from common.tests import _test_net_up
from getikeconf import get_ike_config

srcdir = Path(__file__).absolute().parent
etcdir = srcdir / "etc"


@pytest.fixture(scope="module", autouse=True)
async def network_up(unet, pytestconfig):
    ipv6 = pytestconfig.getoption("--enable-ipv6", False)

    # # Copy new configs then reload swanctl
    # logging.info("copying strongswan config files")
    # for rname, confargs in (("r1", (2, 3)), ("r2", (3, 2))):
    #     rn = unet.hosts[rname]
    #     args = "-q -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null"
    #     args += f" -i {srcdir}/../../root-key"
    #     unet.cmd_raises(f"scp {args} -pr {etcdir}/* root@{rname}:/etc")

    logging.info("copying strongswan config files")
    for rname, confargs in (("r1", (2, 3)), ("r2", (3, 2))):
        logging.info("Configuring IKE on %s", rname)
        rn = unet.hosts[rname]
        conf = get_ike_config(*confargs)
        rn.cmd_raises("cat > /etc/swanctl/conf.d/tunnel.conf", stdin=conf)
        o = rn.cmd_raises("swanctl --load-all")
        logging.info("loaded: %s", o)

    await _network_up(unet, ipv6=ipv6)

    logging.info("Running swanctl on r1")
    r1 = unet.hosts["r1"]
    o = r1.cmd_raises("swanctl --initiate --child linux-1")
    logging.info("swantctl returns: %s", o)


async def test_net_up(unet):
    await _test_net_up(unet)


# async def test_strongswan(unet, astepf, pytestconfig):
#     pass
