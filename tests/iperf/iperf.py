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
import re
import subprocess
import time
from pathlib import Path

import pytest
from common.config import setup_policy_tun, setup_routed_tun
from common.util import start_profile, stop_profile
from munet.base import cmd_error
from munet.testing.util import async_pause_test
from munet.watchlog import MatchFoundError

skip_future = []


def std_result(o, e):
    o = "\n\tstdout: " + o.strip() if o and o.strip() else ""
    e = "\n\tstderr: " + e.strip() if e and e.strip() else ""
    return o + e


def convnum(val, letter):
    val = float(val)
    if not letter:
        return val
    if letter == "K" or letter == "k":
        val *= 1000
    elif letter == "M" or letter == "m":
        val *= 1000000
    elif letter == "G" or letter == "k":
        val *= 1000000000
    elif letter == "T" or letter == "t":
        val *= 1000000000000
    return val


def check_logs(unet):
    for rname in unet.hosts:
        r = unet.hosts[rname]
        regex = re.compile("(Kernel panic|BUG:|Oops:) ")
        for wl in r.watched_logs.values():
            added = wl.snapshot()
            if added:
                logging.debug("check_logs %s on %s added content", wl.path, rname)
                m = regex.search(wl.content)
                if m:
                    return r, wl, m
    return None, None, None


async def _test_iperf(
    unet,
    astepf,
    mode="iptfs",
    ipsec_intf="eth2",
    iptfs_opts="",
    use_iperf3=False,
    use_udp=False,
    udp_brate="500M",
    pktsize=None,
    routed=False,
    ipv6=False,
    tun_ipv6=False,
    profile=False,
    profcount=0,
    tracing=False,
    duration=10,
):
    h1 = unet.hosts["h1"]
    h2 = unet.hosts["h2"]
    r2 = unet.hosts["r2"]

    if routed:
        await setup_routed_tun(
            unet,
            mode=mode,
            ipsec_intf=ipsec_intf,
            iptfs_opts=iptfs_opts,
            ipv6=ipv6,
            tun_ipv6=tun_ipv6,
            tun_route_mtu=65536,
        )
    else:
        await setup_policy_tun(
            unet,
            mode=mode,
            ipsec_intf=ipsec_intf,
            iptfs_opts=iptfs_opts,
            ipv6=ipv6,
            tun_ipv6=tun_ipv6,
            tun_route_mtu=65536,
        )

    # # check the sum inside iptfs code with printk
    # if tun_ipv6:
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

    iperfs = h2.popen(sargs)

    leakcheck = False
    # watch "awk '/^kmalloc-128/{print \$2}'" /proc/slabinfo
    # perfs = None
    try:
        # And then runt he client
        await astepf("Prior to starting client")

        #
        # Enable tracing
        #
        trpath = Path("/sys/kernel/tracing")
        evpath = trpath / "events/iptfs"
        tronpath = trpath / "tracing_on"
        if tracing:
            afpath = trpath / "available_filter_functions"

            evp = evpath / "enable"
            for rname in ["r1", "r2"]:
                r = unet.hosts[rname]
                r.cmd_nostatus(f"echo 1 > {evp}")

                # sfpath = trpath / "set_ftrace_filter"
                # r2.cmd_nostatus(f"grep ^iptfs {afpath} > {sfpath}")
                # ctpath = trpath / "current_tracer"
                # r2.cmd_status(f"echo function > {ctpath}")

                # sfpath = trpath / "set_graph_function"
                # r2.cmd_nostatus(f"grep ^iptfs {afpath} > {sfpath}")
                # ctpath = trpath / "current_tracer"
                # r2.cmd_status(f"echo function_graph > {ctpath}")

                r.cmd_status(f"echo 1 > {tronpath}")

        #
        # Enable leak detect
        #
        dbgpath = Path("/sys/kernel/debug")
        leakpath = dbgpath / "kmemleak"
        if leakcheck:
            # r2.cmd_status(f"echo scan=off > {leakpath}")
            for rname in ["r1", "r2"]:
                r = unet.hosts[rname]
                rc, _, _ = r.cmd_status(f"test -e {leakpath}", warn=False)
                if rc:
                    logging.info("Disabling leakcheck as not enabled in kernel")
                    leakcheck = False
                    break
                r.cmd_status(f"echo clear > {leakpath}")

        if use_udp:
            cargs = ["-u", "-b", udp_brate, "-l", pktsize]
        else:
            cargs = ["-M", pktsize] if pktsize else []
            if not use_iperf3:
                cargs.append("-m")  # print mss
                if ipv6:
                    cargs.append("-V")

        tval = duration

        if use_iperf3:
            args = [
                "iperf3",
                # "--verbose",
                # "--get-server-output",
                # "--port=5201",
                # "--json",
                "-P",
                "8",
                "-t",
                str(tval),  # timeval
                # "-n",
                # "40K",
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
        perfc = start_profile(unet, "r1", tval + 1) if profile else None

        logging.info("Starting iperf client on h1 for %s", tval)
        # logging.info("Starting iperf3 client on h1 at %s for %s", brate, tval)
        # -M 682 fast, -M 681 superslow, probably the point we aggregate

        result = None
        iperfc = h1.popen(args)
        # iperfc = await h1.async_popen(args)
        rc = None
        try:
            # try:
            #     rc = await asyncio.wait_for(iperfc.wait(), timeout=tval + 5)
            #     timeout = False
            # except asyncio.exceptions.CancelledError:
            #     iperfc.terminate()
            #     rc = await iperfc.wait()
            #     timeout = True
            # o, e = await iperfc.communicate()
            try:
                if tval > 60:
                    rc = iperfc.wait(timeout=tval + 20)
                else:
                    rc = iperfc.wait(timeout=tval + 5)
                timeout = False
            except subprocess.TimeoutExpired:
                logging.error("Timeout expired!")
                h1.cmd_status("pkill iperf3")
                time.sleep(1)
                iperfc.kill()
                timeout = True
            # Apparently iperfc is really hanging hard b/c kill is still leaving it around
            try:
                o, e = iperfc.communicate(timeout=5)
                logging.debug("iperf client output: %s", std_result(o, e))
            except subprocess.TimeoutExpired:
                logging.error("timeout after kill")
                logging.error(unet.cmd_nostatus("ps xaww"))
                o = e = ""
                timeout = True

            # await async_pause_test(f"{'' if timeout else 'no '} timeout")

            assert not timeout, f"client TIMEOUT"
            assert not rc, f"client FAILED: {cmd_error(rc, o, e)}"

            #
            # Get results
            #
            # [  5]   0.00-10.00  sec   154 MBytes   129 Mbits/sec  190             sender
            # [  5]   0.00-10.00  sec  6.82 GBytes  5.86 Gbits/sec  368             sender
            m = re.search(
                r"\[\s*\d+\]\s+[-0-9\.]+\s+sec.+\s+([0-9 \.]+) ([KMGT])?bits/sec\s+(\d+)?\s*sender",
                o,
            )
            if m:
                quant = float(m.group(1))
                value = quant
                mletter = m.group(2)
                if mletter is None:
                    mletter = ""
                else:
                    value = convnum(value, mletter)
                retries = int(m.group(3)) if m.group(3) else 0
                result = [value, retries, quant, mletter]
                logging.info(
                    "iperf client completed, avg bitrate: %s %sbits/s", quant, mletter
                )
            else:
                logging.info(
                    "iperf client completed -- no result found:\n%s", std_result(o, e)
                )

            #
            # Look for specific type of leak
            #
            if True:
                vals = r2.cmd_nostatus(
                    r"awk '/^kmalloc-(128|256|512|2k)/{print $1, $2;}' /proc/slabinfo"
                )
                vals = [x.split() for x in vals.split("\n") if x.strip()]
                vals = [(x[0], int(x[1])) for x in vals]
                for k, v in vals:
                    if v > 30000:
                        logging.info("Large num of alloc'd %s: %s", k, v)

            else:
                vals = r2.cmd_nostatus(
                    "awk '/^kmalloc-(128|256|512|2k)/{print $1, $2;}' /proc/slabinfo"
                )
                vals = [int(x.strip()) for x in vals.split("\n") if x.strip()]
                assert (
                    vals[0] < 50000 and vals[1] < 50000
                ), f"leak found on r2 kmalloc-128|256|512|2k == {vals}"

            if leakcheck:
                for rname in ["r1", "r2"]:
                    r = unet.hosts[rname]
                    r.cmd_status(f"echo scan > {leakpath}")
                    assert not r.cmd_nostatus(
                        f"head {leakpath}"
                    ).strip(), f"leaks found on {rname}"

            if perfc:
                stop_profile(perfc, filebase=f"perf-{profcount}.data")
                perfc = None
            # result = json.loads(o)
            # logging.info("Results: %s", json.dumps(result, sort_keys=True, indent=2))
        finally:
            if perfc:
                stop_profile(perfc, filebase=f"perf-{profcount}.data")
                perfc = None
            if tracing:
                # disable tracing
                for rname in ["r1", "r2"]:
                    r = unet.hosts[rname]
                    r.cmd_status(f"echo 0 > {tronpath}")
                    # ur2.cmd_status("gzip -c /sys/kernel/tracing/trace > /tmp/trace.gz")
                    trfile = unet.rundir.joinpath(f"{r.name}-trace.txt")
                    with open(trfile, "w+", encoding="ascii") as f:
                        rc, _, e = r.cmd_status(
                            "cat /sys/kernel/tracing/trace", stdout=f
                        )

            if leakcheck:
                for rname in ["r1", "r2"]:
                    r = unet.hosts[rname]
                    r.cmd_status(f"echo scan > {leakpath}")

                o = r.cmd_nostatus(f"head {leakpath}")
                if o.strip():
                    leakfile = unet.rundir.joinpath(f"{r.name}-leaks.txt")
                    with open(leakfile, "w+", encoding="ascii") as f:
                        rc, _, e = r.cmd_status("head -n1000 {leakpath}", stdout=f)

            if iperfc.returncode is None:
                iperfc.terminate()
    finally:
        if iperfs.returncode is None:
            h2.cmd_status("pkill iperf3")
            time.sleep(1)
            iperfs.kill()

        rname, wl, m = check_logs(unet)
        if m:
            skip_future.append(True)
            startpos = m.span()[0]
            content_after = wl.content[startpos:]
            pytest.fail(f"failed log check: {rname}:{wl.path}: {content_after}")

    return result
