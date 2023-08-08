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
from pathlib import Path

import pytest
from common.config import _network_up3
from common.tests import _test_net_up3
from getikeconf import get_ike_config
from munet.testing.fixtures import _unet_impl

srcdir = Path(__file__).absolute().parent
etcdir = srcdir / "etc"


@pytest.fixture(scope="module", name="unet")
async def _unet(rundir_module, pytestconfig):
    async for x in _unet_impl(rundir_module, pytestconfig, param="munet3"):
        yield x


@pytest.fixture(scope="module", autouse=True)
async def network_up3(unet, pytestconfig):
    ipv6 = pytestconfig.getoption("--enable-ipv6", False)

    # # Copy new configs then reload swanctl
    # logging.info("copying strongswan config files")
    # for rname, confargs in (("r1", (2, 4)), ("r2", (4, 2))):
    #     rn = unet.hosts[rname]
    #     # If routers are not qemu/image then we need to copy swan configs
    #     args = "-q -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null"
    #     args += f" -i {srcdir}/../../root-key"
    #     unet.cmd_raises(f"scp {args} -pr {etcdir}/* root@{rname}:/etc")

    for rname, confargs in (("r1", (2, 4)), ("r2", (4, 2))):
        logging.info("Configuring IKE on %s", rname)
        rn = unet.hosts[rname]

        # # This file has already been parsed at this point.
        # logpath = str(Path(rn.rundir) / "charon.log")
        # conf = logging_config.format(logpath)
        # rn.cmd_raises("cat > /etc/strongswan.d/00logging.conf", stdin=conf)

        conf = get_ike_config(*confargs)
        rn.cmd_raises("cat > /etc/swanctl/conf.d/tunnel.conf", stdin=conf)
        o = rn.cmd_raises("swanctl --load-all")
        logging.info("loaded: %s", o)

    await _network_up3(unet, ipv6=ipv6, minimal=True)

    logging.info("Running swanctl on r1")
    r1 = unet.hosts["r1"]
    o = r1.cmd_raises("swanctl --initiate --child linux-1")
    logging.info("swantctl returns: %s", o)


async def test_net_up(unet):
    await _test_net_up3(unet, minimal=True)


# async def test_strongswan(unet, astepf, pytestconfig):
#     pass


logging_config = """
charon {{
    filelog {{
        debug-log {{
            path = {0}
            time_format = %b %e %T
            ike_name = yes
            default = 1
            flush_line = yes

            ike = 3
            net = 4
            cfg = 1
            lib = 4
            knl = 4
        }}
    }}
    syslog {{
        identifier = charon-custom
        daemon {{
        }}
        auth {{
            default = -1
            ike = 0
        }}
    }}
}}
"""
