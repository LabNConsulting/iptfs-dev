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
"Common tests."
import asyncio
import logging


async def _test_net_up(unet, mgmt0=True, ipv4=True, ipv6=False, multihop=True):
    h1 = unet.hosts["h1"]
    h2 = unet.hosts["h2"]
    r1 = unet.hosts["r1"]

    if ipv4:
        if mgmt0:
            # pings mgmt0 bridge
            logging.debug(h1.cmd_nostatus("ping -c1 192.168.0.254", warn=False))
            logging.debug(h1.cmd_raises("ping -c1 192.168.0.254"))
        # h1 pings r1 (qemu side)
        logging.debug(h1.cmd_nostatus("ping -c1 10.0.0.2", warn=False))
        logging.debug(h1.cmd_raises("ping -c1 10.0.0.2"))
        # h1 pings r1 (other side)
        logging.debug(h1.cmd_nostatus("ping -c1 10.0.1.2", warn=False))
        logging.debug(h1.cmd_raises("ping -c1 10.0.1.2"))

        if mgmt0:
            # r1 (qemu side) pings mgmt0 brige
            logging.debug(r1.conrepl.cmd_nostatus("ping -c1 192.168.0.254"))
            logging.debug(r1.conrepl.cmd_raises("ping -c1 192.168.0.254"))
        # r1 (qemu side) pings h1
        logging.debug(r1.conrepl.cmd_nostatus("ping -c1 10.0.0.1"))
        logging.debug(r1.conrepl.cmd_raises("ping -c1 10.0.0.1"))
        # r1 (qemu side) pings r2 (qemu side)
        logging.debug(r1.conrepl.cmd_nostatus("ping -c1 10.0.1.3"))
        logging.debug(r1.conrepl.cmd_raises("ping -c1 10.0.1.3"))

        if mgmt0:
            # h2 pings mgmt0 bridge
            logging.debug(h2.cmd_nostatus("ping -c1 192.168.0.254", warn=False))
            logging.debug(h2.cmd_raises("ping -c1 192.168.0.254"))
        # h2 pings r2 (qemu side)
        logging.debug(h2.cmd_nostatus("ping -c1 10.0.2.3", warn=False))
        logging.debug(h2.cmd_raises("ping -c1 10.0.2.3"))
        # h2 pings r2 (other side)
        logging.debug(h2.cmd_nostatus("ping -c1 10.0.1.3", warn=False))
        logging.debug(h2.cmd_raises("ping -c1 10.0.1.3"))

        #
        # Ping multi-hop after single
        #

        if multihop:
            # We don't add these routes after clean-config so don't test for them
            # h1 pings r2
            # logging.debug(h1.cmd_nostatus("ping -c1 10.0.1.3", warn=False))
            # logging.debug(h1.cmd_raises("ping -c1 10.0.1.3"))

            # h1 pings h2
            logging.debug(h1.cmd_nostatus("ping -c1 10.0.2.4", warn=False))
            logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))

            # We don't add these routes after clean-config so don't test for them
            # h2 pings r1
            # logging.debug(h2.cmd_nostatus("ping -c1 10.0.1.2", warn=False))
            # logging.debug(h2.cmd_raises("ping -c1 10.0.1.2"))

            # h2 pings h1
            logging.debug(h2.cmd_nostatus("ping -c1 10.0.0.1", warn=False))
            logging.debug(h2.cmd_raises("ping -c1 10.0.0.1"))

    if ipv6:
        # Don't use short deadlines NDisc requires more time than arp.
        if mgmt0:
            # pings mgmt0 bridge
            logging.debug(h1.cmd_nostatus("ping -c1 fd00::ff", warn=False))
            logging.debug(h1.cmd_raises("ping -c1 fd00::ff"))
        # h1 pings r1 (qemu side)
        logging.debug(h1.cmd_nostatus("ping -c1 fc00:0:0:0::2", warn=False))
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:0::2"))
        # h1 pings r1 (other side)
        logging.debug(h1.cmd_nostatus("ping -c1 fc00:0:0:1::2", warn=False))
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:1::2"))

        if mgmt0:
            # r1 (qemu side) pings mgmt0 brige
            logging.debug(r1.conrepl.cmd_nostatus("ping -c1 fd00::ff"))
            logging.debug(r1.conrepl.cmd_raises("ping -c1 fd00::ff"))
        # r1 (qemu side) pings h1
        logging.debug(r1.conrepl.cmd_nostatus("ping -c1 fc00:0:0:0::1"))
        logging.debug(r1.conrepl.cmd_raises("ping -c1 fc00:0:0:0::1"))
        # r1 (qemu side) pings r2 (qemu side)
        logging.debug(r1.conrepl.cmd_nostatus("ping -c1 fc00:0:0:1::3"))
        logging.debug(r1.conrepl.cmd_raises("ping -c1 fc00:0:0:1::3"))

        if mgmt0:
            # h2 pings mgmt0 bridge
            logging.debug(h2.cmd_nostatus("ping -c1 fd00::ff", warn=False))
            logging.debug(h2.cmd_raises("ping -c1 fd00::ff"))
        # h2 pings r2 (qemu side)
        logging.debug(h2.cmd_nostatus("ping -c1 fc00:0:0:2::3", warn=False))
        logging.debug(h2.cmd_raises("ping -c1 fc00:0:0:2::3"))
        # h2 pings r2 (other side)
        logging.debug(h2.cmd_nostatus("ping -c1 fc00:0:0:1::3", warn=False))
        logging.debug(h2.cmd_raises("ping -c1 fc00:0:0:1::3"))

        #
        # Ping multi-hop after single
        #

        if multihop:
            # We don't add these routes after clean-config so don't test for them
            # # h1 pings r2
            # logging.debug(h1.cmd_nostatus("ping -c1 fc00:0:0:1::3", warn=False))
            # logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:1::3"))

            # # h1 pings h2
            logging.debug(h1.cmd_nostatus("ping -c1 fc00:0:0:2::4", warn=False))
            logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))

            # We don't add these routes after clean-config so don't test for them
            # # h2 pings r1
            # logging.debug(h2.cmd_nostatus("ping -c1 fc00:0:0:1::2", warn=False))
            # logging.debug(h2.cmd_raises("ping -c1 fc00:0:0:1::2"))

            # h2 pings h1
            logging.debug(h2.cmd_nostatus("ping -c1 fc00:0:0:0::1", warn=False))
            logging.debug(h2.cmd_raises("ping -c1 fc00:0:0:0::1"))


async def _test_net_up3(unet, mgmt0=True, ipv4=True, ipv6=False, minimal=False):
    h1 = unet.hosts.get("h1")
    h2 = unet.hosts.get("h2")
    r1 = unet.hosts.get("r1")
    r2 = unet.hosts.get("r2")
    rm = unet.hosts.get("rm")

    r1con = r1.conrepl if r1 else None
    r2con = r2.conrepl if r2 else None

    if ipv4:
        # pings mgmt0 bridge
        if mgmt0:
            logging.debug(h1.cmd_nostatus("ping -c1 192.168.0.254"))
            logging.debug(h1.cmd_raises("ping -c1 192.168.0.254"))
            logging.debug(rm.cmd_nostatus("ping -c1 192.168.0.254"))
            logging.debug(rm.cmd_raises("ping -c1 192.168.0.254"))
            logging.debug(h2.cmd_nostatus("ping -c1 192.168.0.254"))
            logging.debug(h2.cmd_raises("ping -c1 192.168.0.254"))
            logging.debug(r1con.cmd_nostatus("ping -c1 192.168.0.254"))
            logging.debug(r1con.cmd_raises("ping -c1 192.168.0.254"))
            logging.debug(r2con.cmd_nostatus("ping -c1 192.168.0.254"))
            logging.debug(r2con.cmd_raises("ping -c1 192.168.0.254"))

        logging.debug(h1.cmd_nostatus("ping -c1 10.0.0.2"))
        logging.debug(h1.cmd_raises("ping -c1 10.0.0.2"))

        logging.debug(r1con.cmd_nostatus("ping -c1 10.0.1.3"))
        logging.debug(r1con.cmd_raises("ping -c1 10.0.1.3"))

        # logging.debug(r1con.cmd_nostatus("ping -c1 10.0.2.4"))
        # logging.debug(r1con.cmd_raises("ping -c1 10.0.2.4"))

        # logging.debug(r2con.cmd_nostatus("ping -c1 10.0.1.3"))
        # logging.debug(r2con.cmd_raises("ping -c1 10.0.1.3"))

        logging.debug(r2con.cmd_nostatus("ping -c1 10.0.2.4"))
        logging.debug(r2con.cmd_raises("ping -c1 10.0.2.4"))

        logging.debug(h2.cmd_nostatus("ping -c1 10.0.3.4"))
        logging.debug(h2.cmd_raises("ping -c1 10.0.3.4"))

        if not minimal:
            logging.debug(h1.cmd_nostatus("ping -c1 10.0.1.2"))
            logging.debug(h1.cmd_raises("ping -c1 10.0.1.2"))

            logging.debug(h1.cmd_nostatus("ping -c1 10.0.1.3"))
            logging.debug(h1.cmd_raises("ping -c1 10.0.1.3"))

            logging.debug(h1.cmd_nostatus("ping -c1 10.0.2.3"))
            logging.debug(h1.cmd_raises("ping -c1 10.0.2.3"))

            logging.debug(h1.cmd_nostatus("ping -c1 10.0.2.4"))
            logging.debug(h1.cmd_raises("ping -c1 10.0.2.4"))

            logging.debug(h1.cmd_nostatus("ping -c1 10.0.3.4"))
            logging.debug(h1.cmd_raises("ping -c1 10.0.3.4"))

            logging.debug(h1.cmd_nostatus("ping -c1 10.0.3.5"))
            logging.debug(h1.cmd_raises("ping -c1 10.0.3.5"))

            logging.debug(h2.cmd_nostatus("ping -c1 10.0.2.4"))
            logging.debug(h2.cmd_raises("ping -c1 10.0.2.4"))

            logging.debug(h2.cmd_nostatus("ping -c1 10.0.2.3"))
            logging.debug(h2.cmd_raises("ping -c1 10.0.2.3"))

            logging.debug(h2.cmd_nostatus("ping -c1 10.0.1.3"))
            logging.debug(h2.cmd_raises("ping -c1 10.0.1.3"))

            logging.debug(h2.cmd_nostatus("ping -c1 10.0.1.2"))
            logging.debug(h2.cmd_raises("ping -c1 10.0.1.2"))

            logging.debug(h2.cmd_nostatus("ping -c1 10.0.0.2"))
            logging.debug(h2.cmd_raises("ping -c1 10.0.0.2"))

            logging.debug(h2.cmd_nostatus("ping -c1 10.0.0.1"))
            logging.debug(h2.cmd_raises("ping -c1 10.0.0.1"))

    if ipv6:
        # Don't use short deadlines NDisc requires more time than arp.
        if mgmt0:
            # pings mgmt0 bridge
            logging.debug(h1.cmd_nostatus("ping -c1 fd00::ff"))
            logging.debug(h1.cmd_raises("ping -c1 fd00::ff"))
            logging.debug(h2.cmd_nostatus("ping -c1 fd00::ff"))
            logging.debug(h2.cmd_raises("ping -c1 fd00::ff"))
            logging.debug(rm.cmd_nostatus("ping -c1 fd00::ff"))
            logging.debug(rm.cmd_raises("ping -c1 fd00::ff"))
            logging.debug(r1con.cmd_nostatus("ping -c1 fd00::ff"))
            logging.debug(r1con.cmd_raises("ping -c1 fd00::ff"))
            logging.debug(r2con.cmd_nostatus("ping -c1 fd00::ff"))
            logging.debug(r2con.cmd_raises("ping -c1 fd00::ff"))

        logging.debug(h1.cmd_nostatus("ping -c1 fc00:0:0:0::2"))
        logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:0::2"))

        logging.debug(r1con.cmd_nostatus("ping -c1 fc00:0:0:1::3"))
        logging.debug(r1con.cmd_raises("ping -c1 fc00:0:0:1::3"))

        # logging.debug(r1con.cmd_nostatus("ping -c1 fc00:0:0:2::4"))
        # logging.debug(r1con.cmd_raises("ping -c1 fc00:0:0:2::4"))

        # logging.debug(r2con.cmd_nostatus("ping -c1 fc00:0:0:1::3"))
        # logging.debug(r2con.cmd_raises("ping -c1 fc00:0:0:1::3"))

        logging.debug(r2con.cmd_nostatus("ping -c1 fc00:0:0:2::4"))
        logging.debug(r2con.cmd_raises("ping -c1 fc00:0:0:2::4"))

        logging.debug(h2.cmd_nostatus("ping -c1 fc00:0:0:3::4"))
        logging.debug(h2.cmd_raises("ping -c1 fc00:0:0:3::4"))

        if not minimal:
            logging.debug(h1.cmd_nostatus("ping -c1 fc00:0:0:1::2"))
            logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:1::2"))

            logging.debug(h1.cmd_nostatus("ping -c1 fc00:0:0:1::3"))
            logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:1::3"))

            logging.debug(h1.cmd_nostatus("ping -c1 fc00:0:0:2::3"))
            logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::3"))

            logging.debug(h1.cmd_nostatus("ping -c1 fc00:0:0:2::4"))
            logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:2::4"))

            logging.debug(h1.cmd_nostatus("ping -c1 fc00:0:0:3::4"))
            logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:3::4"))

            logging.debug(h1.cmd_nostatus("ping -c1 fc00:0:0:3::5"))
            logging.debug(h1.cmd_raises("ping -c1 fc00:0:0:3::5"))

            logging.debug(h2.cmd_nostatus("ping -c1 fc00:0:0:2::4"))
            logging.debug(h2.cmd_raises("ping -c1 fc00:0:0:2::4"))

            logging.debug(h2.cmd_nostatus("ping -c1 fc00:0:0:1::3"))
            logging.debug(h2.cmd_raises("ping -c1 fc00:0:0:1::3"))

            logging.debug(h2.cmd_nostatus("ping -c1 fc00:0:0:2::3"))
            logging.debug(h2.cmd_raises("ping -c1 fc00:0:0:2::3"))

            logging.debug(h2.cmd_nostatus("ping -c1 fc00:0:0:1::2"))
            logging.debug(h2.cmd_raises("ping -c1 fc00:0:0:1::2"))

            logging.debug(h2.cmd_nostatus("ping -c1 fc00:0:0:0::2"))
            logging.debug(h2.cmd_raises("ping -c1 fc00:0:0:0::2"))

            logging.debug(h2.cmd_nostatus("ping -c1 fc00:0:0:0::1"))
            logging.debug(h2.cmd_raises("ping -c1 fc00:0:0:0::1"))
