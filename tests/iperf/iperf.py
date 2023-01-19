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
import logging

from common.config import setup_policy_tun, setup_routed_tun
from common.util import start_profile, stop_profile
from munet.base import cmd_error


async def _test_iperf(
    unet,
    astepf,
    ipsec_intf,
    iptfs_opts="",
    use_iperf3=False,
    use_udp=False,
    udp_brate="500M",
    pktsize=None,
    routed=False,
    ipv6=False,
    profile=False,
    profcount=0,
):
    h1 = unet.hosts["h1"]
    r1 = unet.hosts["r1"]
    h2 = unet.hosts["h2"]

    if routed:
        await setup_routed_tun(
            unet, ipsec_intf=ipsec_intf, iptfs_opts=iptfs_opts, ipv6=ipv6
        )
    else:
        await setup_policy_tun(
            unet, ipsec_intf=ipsec_intf, iptfs_opts=iptfs_opts, ipv6=ipv6
        )

    # # check the sum inside iptfs code with printk
    # if ipv6:
    #     pktsize = "536"
    # else:
    #     # pktsize = "189"
    #     pktsize = "536"
    # pktsize = None

    logging.info("Starting iperf server on h2")
    sargs = ["iperf3" if use_iperf3 else "iperf", "-s"]
    if not use_iperf3:
        if use_udp:
            sargs.append("-u")
        sargs.append("-V")  # ipv4 or ipv6
    iperfs = await h2.async_popen(sargs)

    # perfs = None
    try:
        # And then runt he client
        await astepf("Prior to starting client")

        if use_udp:
            cargs = ["-u", "-b", udp_brate, "-l", pktsize]
        else:
            cargs = ["-M", pktsize] if pktsize else []
            if not use_iperf3:
                cargs.append("-m")  # print mss
                if ipv6:
                    cargs.append("-V")

        tval = 10

        if use_iperf3:
            args = [
                "iperf3",
                "--verbose",
                "--get-server-output",
                # "--port=5201",
                # "--json",
                "-t",
                str(tval),  # timeval
                # "-P4",  # parallel threads
                # "--bidir",
                # "--repeating-payload",
                *cargs,
                # "-w", "2M",
                "-c",  # client
                f"{h2.get_intf_addr('eth1', ipv6=ipv6).ip}",
            ]
        else:
            args = [
                "iperf",
                *cargs,
                # "-p",
                # "5202",
                "-e",  # enhanced reporting
                "-t",
                str(tval),  # timeval
                # "-P4",  # parallel threads
                # "--incr-srcport", # increment src port for threads
                # "--dualtest",
                "-z",  # req realtime schedule
                # "-w4m",
                "-c",  # client
                f"{h2.get_intf_addr('eth1', ipv6=ipv6).ip}",
            ]

        # Start profiling if enabled
        perfc = await start_profile(unet, "r1", tval + 1) if profile else None

        logging.info("Starting iperf client on h1 for %s", tval)
        # logging.info("Starting iperf3 client on h1 at %s for %s", brate, tval)
        # -M 682 fast, -M 681 superslow, probably the point we aggregate

        iperfc = await h1.async_popen(args)
        try:
            rc = await iperfc.wait()
            if rc:
                logging.info("iperf client completed")
            else:
                logging.warning("iperf client (on h1) exited with code: %s", rc)
                o, e = await iperfc.communicate()
                o = o.decode("utf-8")
                e = e.decode("utf-8")
                assert not rc, f"client failed: {cmd_error(rc, o, e)}"

            if perfc:
                await stop_profile(perfc, filebase=f"perf-{profcount}.data")
                perfc = None
            # result = json.loads(o)
            # logging.info("Results: %s", json.dumps(result, sort_keys=True, indent=2))
        finally:
            if perfc:
                await stop_profile(perfc, filebase=f"perf-{profcount}.data")
                perfc = None
            if iperfc.returncode is None:
                iperfc.terminate()
    finally:
        if iperfs.returncode is None:
            iperfs.terminate()
