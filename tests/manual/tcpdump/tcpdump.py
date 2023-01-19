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
import asyncio
import logging
import os
import signal
import subprocess

from common.config import setup_policy_tun
from munet.base import cmd_error


async def _test_iperf(unet, astepf, ipsec_intf, profile=True, ipv6=False):
    h1 = unet.hosts["h1"]
    r1 = unet.hosts["r1"]
    h2 = unet.hosts["h2"]

    await setup_policy_tun(unet, ipsec_intf=ipsec_intf, ipv6=ipv6)

    # Let's open an iperf3 process on h2.
    iperf3 = False
    use_udp = 0
    udp_brate = "500M"

    # check the sum inside iptfs code with printk

    if ipv6:
        pktsize = "536"
    else:
        # pktsize = "189"
        pktsize = "536"
    # pktsize = None

    logging.info("Starting iperf server on h2")
    sargs = ["iperf3" if iperf3 else "iperf", "-s"]
    if not iperf3 and use_udp:
        sargs.append("-u")
    iperfs = await h2.async_popen(sargs)

    # perfs = None
    try:
        # And then runt he client
        await astepf("Prior to starting client")

        if use_udp:
            cargs = ["-u", "-b", udp_brate, "-l", pktsize]
        else:
            cargs = ["-M", pktsize] if pktsize else []
            if not iperf3:
                cargs.append("-m")

        tval = 10

        if iperf3:
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
                f"{h2.get_intf_addr('eth1', ipv6=True).ip}",
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
                f"{h2.get_intf_addr('eth1', ipv6=True).ip}",
            ]

        if profile:
            perfargs = [
                "perf",
                "record",
                "-F",
                "997",
                "-a",
                "-g",
                "-o",
                "/tmp/perf.data",
                "--",
                "sleep",
                tval + 1,
            ]

        perfc = None
        if profile:
            await r1.async_cmd_raises("sysctl -w kernel.perf_cpu_time_max_percent=75")
            logging.info("Starting perf-profile on r1 for %s", tval + 1)
            perfc = await r1.async_popen(perfargs)

        logging.info("Starting iperf client on h1 for %s", tval)
        # logging.info("Starting iperf3 client on h1 at %s for %s", brate, tval)
        # -M 682 fast, -M 681 superslow, probably the point we aggregate

        iperfc = await h1.async_popen(args)
        try:
            rc = await iperfc.wait()
            logging.info("iperf client on h1 completed rc %s", rc)
            o, e = await iperfc.communicate()
            o = o.decode("utf-8")
            e = e.decode("utf-8")
            assert not rc, f"client failed: {cmd_error(rc, o, e)}"

            if profile:
                # We need some sort of timeout here.
                try:
                    logging.info("signaling perf to exit")
                    perfc.send_signal(signal.SIGHUP)
                    logging.info("waiting for perf to exit")
                    o, e = await asyncio.wait_for(perfc.communicate(), timeout=2.0)
                except TimeoutError:
                    logging.warning(
                        "perf didn't finish after signal rc: %s", perfc.returncode
                    )
                    raise
                logging.info("perf rc: %s output: %s error: %s", perfc.returncode, o, e)
            logging.info("Results: %s", o)
            # result = json.loads(o)
            # logging.info("Results: %s", json.dumps(result, sort_keys=True, indent=2))
        finally:
            if perfc:
                try:
                    perfc.terminate()
                    o, e = await perfc.communicate()
                    logging.warning(
                        "perf rc: %s output: %s error: %s", perfc.returncode, o, e
                    )
                except Exception as error:
                    logging.warning(
                        "ignoring error terminating perf profiling: %s", error
                    )
            if iperfc.returncode is None:
                iperfc.terminate()
    finally:
        if iperfs.returncode is None:
            iperfs.terminate()


async def _test_tcp(unet, astepf):
    h1 = unet.hosts["h1"]
    h2 = unet.hosts["h2"]
    r1 = unet.hosts["r1"]
    r2 = unet.hosts["r2"]

    await setup_policy_tun(unet)

    # # Keep everything SUPER simple
    # for host in (r1, r2):
    #     host.comrepl.cmd_raises("ethtool -K eth1 tx off sg off tso off rx off gso off")
    #     host.comrepl.cmd_raises("ethtool -K eth2 tx off sg off tso off rx off gso off")
    #     # host.cmd_raises("ethtool -K eth1 tso off gso off")
    #     # host.cmd_raises("ethtool -K eth2 tso off gso off")
    # for host in (h1, h2):
    #     host.cmd_raises("sysctl -w net.ipv4.ip_no_pmtu_disc=1")
    #     host.cmd_raises("sysctl -w net.ipv4.route.min_pmtu=1200")
    #     host.cmd_raises("sysctl -w net.ipv4.tcp_mtu_probing=0")

    # Let's open an tcp process on h2.
    logging.info("Starting TCP server on h2")
    script = os.path.join(unet.config_dirname, "../../common/send-recv.py")
    args = [script, "-s"]
    tcps = await h2.async_popen(args)
    try:
        # And then runt he client
        await astepf("Prior to starting client")
        size = "100M"
        logging.info("Starting tcp client on h1 sending %s bytes", size)
        args = [
            script,
            "-l",
            size,
            f"{h2.get_intf_addr('eth1').ip}",
        ]
        tcpc = await h1.async_popen(args, stderr=subprocess.STDOUT)
        try:
            rc = await tcpc.wait()
            logging.info("tcp client on h1 completed rc %s", rc)
            o, _ = await tcpc.communicate()
            o = o.decode("utf-8")
            assert not rc, f"client failed: {cmd_error(rc, o, '')}"
            if o:
                logging.info('tcp client exits with output: "%s"', o)
            else:
                logging.info("tcp client exits cleanly")
        finally:
            if tcpc.returncode is None:
                tcpc.terminate()
    finally:
        if tcps.returncode is None:
            tcps.terminate()
