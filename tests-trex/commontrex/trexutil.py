# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# July 6 2022, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2022, LabN Consulting, L.L.C.
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
"Utility functions for use with trex"
import asyncio
import copy
import datetime
import json
import logging
import pprint
import re
import time
from dataclasses import dataclass
from pathlib import Path

from common import util

logger = logging.getLogger(__name__)

UINT_NULL = 4294967295
USER_IFINDEX = 1


def find_json_obj(a, k, v):
    for o in a:
        if k in o and o[k] == v:
            return o
    return None


def sub_stats(m, s):
    d = copy.deepcopy(m)
    for o in d:
        if "stats64" not in o or "ifname" not in o:
            continue
        so = find_json_obj(s, "ifname", d["ifname"])
        if not so:
            continue
        rxdo = o["stats64"]["rx"]
        rxso = so["stats64"]["rx"]
        txdo = o["stats64"]["tx"]
        txso = so["stats64"]["tx"]
        for stat in rxdo:
            rxdo[stat] -= rxso[stat]
        for stat in txdo:
            txdo[stat] -= txso[stat]
    return d


def convert_number(value):
    """Convert a number value with a possible suffix to an integer.

    >>> convert_number("100k") == 100 * 1024
    True
    >>> convert_number("100M") == 100 * 1000 * 1000
    True
    >>> convert_number("100Gi") == 100 * 1024 * 1024 * 1024
    True
    >>> convert_number("55") == 55
    True
    """
    if value is None:
        return None
    rate = str(value)
    base = 1000
    if rate[-1] == "i":
        base = 1024
        rate = rate[:-1]
    suffix = "KMGTPEZY"
    index = suffix.find(rate[-1])
    if index == -1:
        base = 1024
        index = suffix.lower().find(rate[-1])
    if index != -1:
        rate = rate[:-1]
    return int(rate) * base ** (index + 1)


@dataclass
class Args:
    """This is a replacement for previous code which used argparse args"""

    def __init__(self, pytestconfig, **kwargs):
        def get_value(name, default):
            uname = name.replace("-", "_")
            defname = "default_" + uname
            defvalue = kwargs.get(defname, default)
            if pytestconfig is None:
                return defvalue
            cvalue = pytestconfig.getoption("--" + name, defvalue)
            if cvalue is None:
                return defvalue
            return cvalue

        self.mode: str = get_value("mode", "iptfs")
        mode = self.mode

        self.cc: bool = get_value("cc", False)
        self.connections: int = get_value("connections", 1)
        self.capture_drops: bool = get_value("capture_drops", False)
        self.dont_use_ipsec: bool = mode == "ipip"
        self.dont_use_tfs: bool = mode == "tunnel"
        self.duration: float = get_value("duration", 10.0)
        self.encap_ipv6: bool = get_value("encap-ipv6", False)
        self.encap_udp: bool = get_value("encap-udp", False)
        self.forward_only: bool = mode == "routed"
        self.gdb: bool = get_value("gdb-routers", False)
        self.pkt_size: int = get_value("pkt-size", 1500)
        self.ipv6_traffic: bool = get_value("ipv6-traffic", False)
        self.is_docker: bool = True
        self.null: bool = get_value("null-encrypt", False)
        self.old_imix: bool = get_value("old-imix", False)
        self.pause: bool = get_value("pause", False)
        self.pause_on_success: bool = get_value("pause-at-end", False)
        self.percentage: float = get_value("percentage", None)
        self.rate: float = convert_number(get_value("rate", "1G"))
        self.unidirectional: int = get_value("unidir", None)
        self.user_pkt_size: int = get_value("user-pkt-size", 0)


def get_check_ports(args, c, default=None):
    ports = c.get_acquired_ports()
    if not ports and default is not None:
        ports = default
    assert len(ports) == 2
    if args.unidirectional is None:
        return ports
    if args.unidirectional == 0:
        return ports[:1]
    assert args.unidirectional == 1
    return ports[1:]


def get_max_client_rate(args, c):
    if not c:
        return None
    max_speed = 0
    ports = get_check_ports(args, c, [0, 1])
    assert ports
    for port in ports:
        stl_port = c.ports[port]
        info = stl_port.get_formatted_info()
        if "supp_speeds" in info and info["supp_speeds"]:
            max_port_speed = max(info["supp_speeds"]) * 1000000
        elif "speed" in info:
            max_port_speed = int(float(info["speed"]) * 1e9)
        else:
            # 10M
            max_port_speed = 10000000
        if max_port_speed > max_speed:
            max_speed = max_port_speed
    return max_speed


def update_table_with_rate(
    args, imix_table, l1_rate, iptfs_mtu, percentage, normalize=False
):
    def mps(x):
        return 46 if x < 46 else x

    pps_sum = sum(x["pps"] for x in imix_table)
    avg_ipsize = sum(mps(x["size"]) * x["pps"] for x in imix_table) / pps_sum
    pps = util.line_rate_to_pps(args, l1_rate, avg_ipsize, iptfs_mtu)
    if percentage:
        pps *= percentage / 100

    if normalize:
        # Adjust the actual PPS to account for non-1 pps values in imix table,
        # Results for passing 1 as pps to trex start
        for x in imix_table:
            x["pps"] *= pps / pps_sum
    else:
        # Adjust the actual PPS to account for non-1 pps values in imix table
        # Results for passing pps as pps to trex start
        for x in imix_table:
            x["pps"] /= pps_sum

    return pps, avg_ipsize, pps_sum


def get_udp_spread_table(args, c):
    del c
    assert args.user_pkt_size

    if args.ipv6_traffic:
        minpkt = 48
    else:
        minpkt = 28

    spread_count = (args.user_pkt_size + 1) - minpkt
    avg_ipsize = sum(range(minpkt, args.user_pkt_size + 1)) / spread_count
    pps = util.line_rate_to_pps(args, args.rate, avg_ipsize, args.pkt_size)
    if args.percentage:
        pps = pps * (args.percentage / 100)

    # if c:
    #     max_speed = get_max_client_rate(c)
    #     max_pps = util.line_rate_to_ip_pps(max_speed, avg_ipsize)
    #     if pps > max_pps:
    #         max_speed_float = max_speed / 1e9
    #         capacity = 100 * max_pps / pps
    #         logger.warning("%s",
    #           (f"Lowering pps from {pps} to {max_pps} due to client max speed"
    #            f"{max_speed_float}GBps ({capacity:.1f}% of tunnel capacity)"))
    #         pps = max_pps

    table = [
        {
            "size": args.user_pkt_size,
            "pps": pps,
            "pg_id": 1,
        }
    ]
    desc = f"Spread (avg: {avg_ipsize}) @ {pps}pps for {args.duration}s"
    return table, pps, avg_ipsize, desc


def get_imix_table(args, c, max_imix_size=1500):
    if args.user_pkt_size:
        ipsize = args.user_pkt_size
        pps = util.line_rate_to_pps(args, args.rate, ipsize, args.pkt_size)
        if args.percentage:
            pps = pps * (args.percentage / 100)

        capacity = 0
        if c:
            max_speed = get_max_client_rate(args, c)
            max_pps = util.line_rate_to_ip_pps(max_speed, ipsize)
            if max_speed > 1e9:
                max_speed_float = f"{max_speed / 1e9}Gbps"
            elif max_speed > 1e6:
                max_speed_float = f"{max_speed / 1e6}Mbps"
            else:
                max_speed_float = f"{max_speed / 1e3}Kbps"
            capacity = 100 * pps / max_pps
            if pps > max_pps:
                logger.warning(
                    "%s",
                    (
                        f"Lowering pps from {pps} to {max_pps} due to client max speed"
                        f" {max_speed_float} ({capacity:.1f}% of tunnel capacity)"
                    ),
                )
                pps = max_pps
                capacity = 100.0

        imix_table = [
            {
                "size": ipsize,
                "pps": pps,
                "pg_id": 1,
            }
        ]
        desc = (
            f"static IP size {ipsize}@{util.get_human_readable(pps)}pps"
            f" {capacity:.1f}% of capacity"
        )
        avg_ipsize = ipsize
    else:
        if args.old_imix:
            imix_table = [
                {
                    "size": 40 if not args.ipv6_traffic else 60,
                    "pps": 28,
                    "isg": 0,
                    "pg_id": 1,
                },
                {
                    "size": 576,
                    "pps": 16,
                    "isg": 0.1,
                    "pg_id": 1,
                },
                {
                    "size": max_imix_size,
                    "pps": 4,
                    "isg": 0.2,
                    "pg_id": 1,
                },
            ]
        else:
            imix_table = [
                {
                    "size": 40 if not args.ipv6_traffic else 60,
                    "pps": 50,
                    "isg": 0,
                    "pg_id": 1,
                },
                {
                    "size": max_imix_size,
                    "pps": 50,
                    "isg": 0.1,
                    "pg_id": 1,
                },
            ]

        pps, avg_ipsize, _ = update_table_with_rate(
            args, imix_table, args.rate, args.pkt_size, args.percentage, True
        )
        capacity = 0
        if c:
            max_speed = get_max_client_rate(args, c)
            max_pps = util.line_rate_to_ip_pps(max_speed, avg_ipsize)
            capacity = 100 * pps / max_pps
        desc = (
            f"imix (avg: {avg_ipsize})@{util.get_human_readable(pps)}pps "
            f" {capacity:.1f}% of capacity"
        )

    return imix_table, pps, avg_ipsize, desc


def clear_stats(c):
    """Clear all statistics.

    CLear all stats (and pcap drop capture if configured) in trex and vpp hosts
    """
    if c is not None:
        c.clear_stats()


async def collect_dut_stats(dutlist):
    async def _collect_dut_stats(dut):
        astats = json.loads(dut.cmd_raises("ip -j -s link show"))
        stats = {x["ifname"]: x for x in astats}
        return stats

    return await asyncio.gather(*[_collect_dut_stats(dut) for dut in dutlist])
    # return {k: v for k, v in stats}


def collect_trex_stats(c, unidir=None):
    stats = c.get_stats()
    stats[0]["rx-missed"] = stats[1]["opackets"] - stats[0]["ipackets"]
    stats[1]["rx-missed"] = stats[0]["opackets"] - stats[1]["ipackets"]

    if unidir == 0:
        stats[0]["rx-missed-pct"] = 0
    elif unidir == 1:
        stats[1]["rx-missed-pct"] = 0

    if unidir == 0 or unidir is None:
        stats[1]["rx-missed-pct"] = (
            100 * (stats[0]["opackets"] - stats[1]["ipackets"]) / stats[0]["opackets"]
        )

    if unidir == 1 or unidir is None:
        stats[0]["rx-missed-pct"] = (
            100 * (stats[1]["opackets"] - stats[0]["ipackets"]) / stats[1]["opackets"]
        )
    return stats


def check_running(dut):
    return not hasattr(dut, "check_running") or dut.check_running()


def get_active_dut(dutlist):
    return dutlist


def check_active_dut(dutlist):
    # active_dutlist = get_active_dut(dutlist)
    # if active_dutlist != dutlist:
    #     for dut in dutlist:
    #         if dut not in active_dutlist:
    #             dut.gather_any_core_info()
    #     raise Exception("Not all DUT are running")
    del dutlist


def wait_for_test_done(
    dutlist, c, check_ports, starttime, endtime, beat_callback, beat_time=1
):
    del dutlist

    beat = datetime.timedelta(0, beat_time)
    nextbeat = starttime + beat

    count = 0
    while not c or c.is_traffic_active(ports=check_ports):
        # if c:
        #     logger.debug("active ports: %s acquired %s", str(c.get_active_ports()),
        #                  str(c.get_active_ports()))
        count += 1
        newnow = datetime.datetime.now()
        if newnow >= nextbeat:
            if beat_callback:
                beat_callback((newnow - starttime).total_seconds())
            newnow = datetime.datetime.now()
            nextbeat = nextbeat + beat
            if nextbeat < newnow:
                nextbeat = newnow + ((newnow - nextbeat) % beat)
                assert nextbeat > newnow

        if newnow > endtime:
            # logger.warning("XXX: Past endtime %s", str(newnow - endtime))
            break

        sleeptime = min(1, (nextbeat - newnow).total_seconds())
        if not beat_callback:
            logger.debug("%s", f"Sleeping {sleeptime} seconds")
        time.sleep(sleeptime)

    if newnow < endtime:
        logger.warning("%s", f"TREX ended too early: {endtime - newnow}")
    else:
        logger.info("TREX: times up")

    if c:
        # Wait an additional 100ms for receiving sent traffic
        c.wait_on_traffic(rx_delay_ms=100)


async def start_trex_cont_test(
    args,
    c,
    dutlist,
    mult,
    get_streams_func,
    imix_table,
    extended_stats=False,
    modeclass=None,
    statsclass=None,
    startingf=None,
    tracing=False,
):
    del extended_stats
    # create two streams
    mult = str(mult)
    duration = float(args.duration) if args.duration is not None else 10

    check_active_dut(dutlist)

    if c:
        c.reset()  # Acquire port 0,1 for $USER

        ports = c.get_acquired_ports()
        assert len(ports) == 2

        check_ports = get_check_ports(args, c)
        # add both streams to ports
        for port in check_ports:
            extra_args = {}
            if args.connections > 1:
                extra_args["nstreams"] = args.connections
            c.add_streams(
                get_streams_func(
                    port % 2,
                    imix_table,
                    modeclass=modeclass,
                    statsclass=statsclass,
                    ipv6=args.ipv6_traffic,
                    **extra_args,
                ),
                ports=port,
            )

    # clear the stats before injecting
    clear_stats(c)
    #     None,
    #     dutlist,
    #     extended_stats,
    #     args.capture_drops,
    #     args.dispatch_trace if not c else None,
    # )

    # # Try sending a short burst of the test to prime the pump.
    # if c:
    #     if args.encap_ipv6:
    #         prime_duration = 1
    #     else:
    #         prime_duration = 0.1
    #     logger.info(
    #         "Pre-starting TREX: to prime the pump: mult: %s duration: %s",
    #         str(mult),
    #         str(prime_duration),
    #     )
    #     c.start(ports=check_ports, mult=mult, duration=prime_duration)
    #     c.wait_on_traffic(rx_delay_ms=100)
    #     # clear_stats(c, dutlist, extended_stats,
    #                   args.capture_drops, args.dispatch_trace)
    #     clear_stats(c)

    # # Start any capture
    pcap_servers = []
    # pcap_servers = pcap_servers_up(args, args.capture_ports)

    if tracing:
        trpath = Path("/sys/kernel/tracing")
        tronpath = trpath / "tracing_on"
        evpath = trpath / "events/iptfs"
        evp = evpath / "enable"
        for r in dutlist:
            r.cmd_nostatus(f"echo 1 > {evp}")
            r.cmd_status(f"echo 1 > {tronpath}")

        # if v.args.event_log_size and not v.args.event_log_startup:
        #     v.vppctl("event-logger restart")
        #     if v.args.event_log_dispatch:
        #         v.vppctl("elog trace api barrier dispatch")
        #     elif v.args.event_log_barrier:
        #         v.vppctl("elog trace api barrier ")

    #
    # Don't bother starting test if a VPP has exited.
    #
    check_active_dut(dutlist)

    # Setup beat callback and end times

    #
    # Start the traffic
    #
    startingfval = await startingf() if startingf else None
    starttime = datetime.datetime.now()
    if c:
        logger.info("Starting TREX: mult: %s duration: %s", str(mult), str(duration))
        c.start(ports=check_ports, mult=mult, duration=duration)

    return starttime, pcap_servers, startingfval


async def end_trex_cont_test(
    unet,
    starttime,
    pcap_servers,
    startingfval,
    args,
    c,
    dutlist,
    beat_callback=None,
    beat_time=1,
    stoppingf=None,
    tracing=False,
    start_vstats=None,
):
    if c:
        check_ports = get_check_ports(args, c)
    duration = float(args.duration) if args.duration is not None else 10
    endtime = starttime + datetime.timedelta(0, duration)

    #
    # wait for active ports done
    #
    wait_for_test_done(
        dutlist, c, check_ports, starttime, endtime, beat_callback, beat_time
    )

    logger.debug("TREX: after wait on traffic")

    if stoppingf:
        await stoppingf(startingfval)

    #
    # gpz workaround
    # ETFS tests have not waited long enough to collect VPP counters after
    # the test runs, causing reported values to be incorrect (low). Waiting
    # a few seconds here yields the correct values.
    #
    time.sleep(1)

    active_dutlist = get_active_dut(dutlist)

    #
    # Stop event logs and captures.
    #
    # cap_offs = {}
    # dispatch_cap_offs = {}

    trpath = Path("/sys/kernel/tracing")
    tronpath = trpath / "tracing_on"

    async def stop_disruptive(r):
        r.cmd_status(f"echo 0 > {tronpath}")
        trfile = unet.rundir.joinpath(f"{r.name}-trace.txt")
        with open(trfile, "w+", encoding="ascii") as f:
            r.cmd_status("cat /sys/kernel/tracing/trace", stdout=f)

    if tracing:
        await asyncio.gather(*[stop_disruptive(x) for x in active_dutlist])

    # #
    # # Get pcap captures
    # #
    # async def pcap_server_done(x):
    #     x.close()
    #     drops = x.count_drops()
    #     if drops:
    #         logger.warning("%s", f"{x.name} dropped {drops} packets")
    # if pcap_servers:
    #     await asyncio.gather(*[pcap_server_done(server) for server in pcap_servers])

    active_dutlist = get_active_dut(active_dutlist)

    #
    # Collect post run stats
    #

    stats = None
    if c:
        stats = collect_trex_stats(c, args.unidirectional)

    vstats = await collect_dut_stats(active_dutlist)
    if start_vstats:
        vstats = sub_stats(vstats, start_vstats)

    active_dutlist = get_active_dut(active_dutlist)

    #
    # Collect captures and logs that could be distruptive to stats.
    #

    logger.debug("Collecting disruptive stats")

    async def collect_disruptive(r):
        trfile = unet.rundir.joinpath(f"{r.name}-trace.txt")
        with open(trfile, "w+", encoding="ascii") as f:
            r.cmd_status("cat /sys/kernel/tracing/trace", stdout=f)

    if tracing:
        for r in asyncio.as_completed([collect_disruptive(x) for x in dutlist]):
            await r

    results = []
    # for vpp in active_dutlist:
    #     results.append(collect_disruptive(vpp))
    for result in results:
        await result

    #
    # Now that we've captured any packets and saved any event logs we safely raise an
    # exception if we had cores/exits
    #
    check_active_dut(dutlist)

    #
    # Log show runtime
    #
    # for i, sr in enumerate(showrun):
    #     name = dutlist[i].name
    #     logger.debug("%s:\n%s", name, sr.replace("\n", f"\n{name}: "))

    #
    # Print packet drops
    #

    # for host, pcapfile in pcap_files.items():
    #     result = cap_offs[host]
    #     pcapfile = pcap_files[host]
    #     logger.warning("%s", f"Have some dropped packets to read {result}")
    #     logger.warning("%s", f"Decoding: {result}")
    #     logger.warning("%s",
    #         run_cmd(f"tcpdump -n -s9014 -vvv -ttttt -e -XX -r {pcapfile}"))

    return stats, vstats, pcap_servers


async def run_trex_cont_test(
    args,
    c,
    unet,
    dutlist,
    mult,
    get_streams_func,
    imix_table,
    extended_stats=False,
    beat_callback=None,
    beat_time=1,
    modeclass=None,
    statsclass=None,
    startingf=None,
    beforewaitf=None,
    stoppingf=None,
    tracing=False,
):

    start_vstats = collect_dut_stats(dutlist)

    starttime, pcap_servers, startingfval = await start_trex_cont_test(
        args,
        c,
        dutlist,
        mult,
        get_streams_func,
        imix_table,
        extended_stats,
        modeclass,
        statsclass,
        startingf,
        tracing=tracing,
    )

    if beforewaitf:
        await beforewaitf(startingfval)

    return await end_trex_cont_test(
        unet,
        starttime,
        pcap_servers,
        startingfval,
        args,
        c,
        dutlist,
        beat_callback,
        beat_time,
        stoppingf,
        tracing=tracing,
        start_vstats=start_vstats,
    )


def fail_test(args, reason, trex_stats, vstats, dutlist=None):
    """Fail the test passing the given reason. If stats are passed in then print the
    stats first.
    """
    del vstats
    logger.info("FAILURE DIAGS:")
    if dutlist is None:
        dutlist = []
    if trex_stats:
        pprint.pprint(trex_stats, indent=4)

    # for _, vpp in enumerate(dutlist):
    #     logger.info("%s", f"VPP HOST: {vpp.host}:")
    #     # We do not want bogus way late stats reported!
    #     # logger.info(vpp.vppctl("show errors"))
    #     # dump_tun_stats(vpp, *vstats[index][-1][1:])
    #     # dump_ifstats_one(vpp, vstats[index])

    if args.pause:
        logger.info("%s", f"Pausing after {reason}")
        result = input('Pausing with testbed UP, RETURN to continue, "p" for PDB: ')
        if result.strip().lower() == "p":
            breakpoint()  # pylint: disable=forgotten-debug-statement
    raise Exception(reason)


def check_missed(args, trex_stats, vstats, dutlist):
    p0missed = trex_stats[0]["rx-missed"]
    p0pct = trex_stats[0]["rx-missed-pct"]
    p1missed = trex_stats[1]["rx-missed"]
    p1pct = trex_stats[1]["rx-missed-pct"]
    #
    # Verify trex received all it sent.
    #
    if p0missed or p1missed:
        reason = (
            f"FAILED: p0missed: {p0missed} ({p0pct}%) p1missed: {p1missed} ({p1pct}%)"
        )
        fail_test(args, reason, trex_stats, vstats, dutlist)

    #
    # Verify trex received all VPP sent.
    #
    # This doesn't work for docker trex and ipsec right now b/c we still get arps
    # apparently?
    #
    if args.is_docker and args.dont_use_tfs:
        return

    # XXX update to linux
    # for i, dut in enumerate(dutlist):
    #     trx = trex_stats[i]["ipackets"]
    #     vuser_tx = vstats[i][dut.USER_IFINDEX]["/if/tx"]
    #     if trx != vuser_tx:
    #         reason = f"FAILED: dut{i}/trex port{i} vuser_tx: {vuser_tx} != prx: {trx}"
    #         fail_test(args, reason, trex_stats, vstats, dutlist)


def log_packet_counts(dutlist, trex_stats, vstats, user_intf):
    assert not dutlist or len(dutlist) == 2
    for i, dut in enumerate(dutlist):
        oi = (i + 1) % 2
        missed = trex_stats[i]["rx-missed"]
        pct = trex_stats[i]["rx-missed-pct"]
        logging.info(
            "%s",
            "TEST INFO TREX: {}->{} tx: {} rx: {} missed: {} missed-pct {}".format(
                i,
                oi,
                trex_stats[i]["opackets"],
                trex_stats[oi]["ipackets"],
                missed,
                pct,
            ),
        )

        # tx = trex_stats[i]["opackets"]
        # rx = vstats[i][user_intf]["stats64"]["rx"]["packets"]
        # missed = tx - rx
        # if missed:
        #     pct = abs((missed / tx) * 100)
        #     # mstr = "missed" if missed > 0 else "extra"
        #     missed = abs(missed)
        #     logging.info(
        #         "%s",
        #         f"TEST INFO TREX->DUT: {i} tx: {tx} "
        #         "rx: {rx} {mstr}: {missed} {mstr}-pct: {pct}",
        #     )

        # tx = vstats[i][user_intf]["stats64"]["tx"]["packets"]
        # rx = trex_stats[i]["ipackets"]
        # missed = tx - rx
        # if missed:
        #     pct = abs((missed / tx) * 100)
        #     # mstr = "missed" if missed > 0 else "extra"
        #     missed = abs(missed)
        #     logging.info(
        #         "%s",
        #         f"TEST INFO DUT->TREX: {i} tx: {tx} "
        #         "rx: {rx} {mstr}: {missed} {mstr}-pct: {pct}",
        #     )


def finish_test(module_name, args, dutlist, trex, trex_stats, vstats, user_intf):
    del module_name
    # save_stats(module_name, "trex-stats", trex_stats)
    # save_stats(module_name, "vpp-stats", vstats)

    if trex:
        if args.percentage is None or args.percentage <= 100:
            check_missed(args, trex_stats, vstats, dutlist)

        # logging.debug("TREX Stats:\n%s" % pprint.pformat(trex_stats, indent=4))

        log_packet_counts(dutlist, trex_stats, vstats, user_intf)

    logging.info("TEST PASSED")

    if args.pause_on_success:
        input("Pausing after test, RETURN to continue")
