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
import asyncio
import datetime
import logging
import pprint
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)

UINT_NULL = 4294967295
USER_IFINDEX = 1


@dataclass
class Args:
    """This is a replacement for previous code which used argparse args"""

    cc: bool = False
    connections: int = 1
    capture_drops: bool = False
    dont_use_ipsec: bool = False
    dont_use_tfs: bool = False
    duration: float = 10.0
    encap_ipv6: bool = False
    encap_udp: bool = False
    forward_only: bool = False
    gdb: bool = False
    iptfs_packet_size: int = 1500
    ipv6_traffic: bool = False
    is_docker: bool = True
    null: bool = False
    old_imix: bool = False
    pause: bool = False
    pause_on_success: bool = False
    percentage: float = None
    rate: float = 0.0
    unidirectional: bool = False
    user_packet_size: int = 0


def get_human_readable(v):
    for suffix in ["", "K", "M", "G"]:
        if v < 1000.0:
            return "%3.03f%s" % (v, suffix)
        v /= 1000
    return "%3.1f%s" % (v, "T")


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


def line_rate_to_ip_pps(l1_rate, ipmtu):
    """Convert an L1 ethernet rate to number of IP packets of ipmtu size per second."""
    # Each IP packet requires 8b l1-preamble 14b l2-hdr 4b l2-crc and 12b l1-gap
    # The frame not including the preamble and inter frame gap must be at least 64b
    # 46b + 14 + 4 == 64
    emtu = 8 + max(64, 14 + ipmtu + 4) + 12
    return float(l1_rate) / (emtu * 8)


def ipsec_overhead(gcm, user_pkt_size=None, ipv6=False, udp=False):
    """Get the IPSEC payload size given a target IPTFS packet size"""
    # IPsec/ESP packets are aligned to 4 byte boundary.
    # target_mtu = target_mtu - (target_mtu % 4)
    if ipv6:
        # 40 - IP header, 8 ESP Header, 2 ESP Footer
        o = 40 + 8 + 2
    else:
        # 20 - IP header, 8 ESP Header, 2 ESP Footer
        o = 20 + 8 + 2
    if user_pkt_size:
        # User + Footer must align to 4 byte boundary
        over = (user_pkt_size + 2) % 4
        if over:
            o += 4 - over
    if udp:
        o += 8
    if gcm:
        o += 8 + 16  # IV + ICV = 1440
    return o


def iptfs_payload_size(target_mtu, gcm, cc=False, ipv6=False, udp=False):
    """Get the IPTFS payload size given a target IPTFS packet size"""
    # IPsec/ESP packets are aligned to 4 byte boundary.
    # target_mtu = target_mtu - (target_mtu % 4)
    assert target_mtu % 4 == 0
    iptfs_hdr_size = 4 if not cc else 24
    return target_mtu - ipsec_overhead(gcm, None, ipv6, udp) - iptfs_hdr_size


def iptfs_payload_rate(l1_rate, target_mtu, gcm, cc=False, ipv6=False, udp=False):
    ps = iptfs_payload_size(target_mtu, gcm, cc, ipv6, udp)
    return line_rate_to_ip_pps(l1_rate, target_mtu) * ps


def line_rate_to_iptfs_encap_pps(
    l1_rate, ipmtu, iptfs_mtu, gcm, cc=False, ipv6=False, udp=False
):
    """Convert an l1 line rate to number of inner IP packets per second for a given
    IP MTU using (or not) GCM encryption
    """
    rate = iptfs_payload_rate(l1_rate, iptfs_mtu, gcm, cc, ipv6, udp)
    input_pps = rate / ipmtu
    return input_pps
    # XXX this max should be based on the *physical* line not on the rate we've
    # chosen.
    # max_pps = line_rate_to_ip_pps(l1_rate, ipmtu)
    # return min(max_pps, input_pps)


def line_rate_to_etfs_encap_pps(
    tunnel_line_rate,
    uf_ip_size,  # size of IP frame in user packets
    tunnel_etfs_mtu,  # size of ethernet payload (== etfs encap framesize)
    macsec_enabled,
):  # true/false
    del macsec_enabled

    uf_eth_size = uf_ip_size + 14

    #
    # Calculate ratio of user frames to tunnel frames. In ETFS
    # this number is not exact because fragments have a six-octet
    # header whereas full-frames have a two-octet header, but we
    # should be able to get reasonably close.
    #
    # Consider two cases (maybe they will reduce to the same formula):
    #
    # 1. Small user frames. Multiple full user frames fit into a
    #    single tunnel frame.
    #
    #    A full user frame takes up 2 + uf_eth_size, so the number
    #    of full frames that fit is:
    #
    #        NF = int(tunnel_etfs_mtu / (2 + uf_eth_size))
    #
    #    The remainder is likely to be filled with two fragments, one
    #    at the head of the tunnel frame and one at the tail. We assume
    #    a uniform distribution of head fragment lengths (i.e., there is
    #    an arbitrary shift of the contents with respect to the tunnel
    #    frame).
    #
    #    The number of actual full user frames in a tunnel packet will
    #    be either NF or NF-1, with a probability depending almost
    #    linearly on the size of the remainder. We will simplify for
    #    now and assume that if the remainder is greater than half the
    #    size of (UF+2), the actual number of full frames is NF, otherwise
    #    it will be NF-1.
    #
    #    The number of fragments will usually be two. I think the edge
    #    cases are improbable enough to ignore for this calculation.
    #
    # 2. Large user frames. Tunnel frames contain either one or two
    #    fragments. I think this case applies any time NF is 0.
    #

    NF = tunnel_etfs_mtu // (2 + uf_eth_size)

    if NF > 0:
        # remainder = tunnel_etfs_mtu - (NF * (2 + uf_eth_size))
        # if remainder > (2 + uf_eth_size) / 2:
        #     full_frame_count = NF
        # else:
        #     full_frame_count = NF - 1

        full_frame_headers_per_tunnel_frame = NF
        fragment_headers_per_tunnel_frame = 2

    else:
        full_frame_headers_per_tunnel_frame = 0
        fragment_headers_per_tunnel_frame = 2

    payload = (
        tunnel_etfs_mtu
        - (2 * full_frame_headers_per_tunnel_frame)
        - (6 * fragment_headers_per_tunnel_frame)
    )

    tunnel_packet_rate = line_rate_to_ip_pps(tunnel_line_rate, tunnel_etfs_mtu - 14)

    tunnel_payload_byte_rate = tunnel_packet_rate * payload

    payload_pps = tunnel_payload_byte_rate / uf_eth_size

    return payload_pps


def line_rate_to_pps(args, l1_rate, ipmtu, iptfs_mtu):
    """Convert an l1 line rate to number of packets per second for a given
    IP MTU using (or not) GCM encryption
    """

    gcm = not args.null
    if args.forward_only:
        pps = line_rate_to_ip_pps(l1_rate, ipmtu)
    elif args.dont_use_ipsec:
        ip_ohead = 20 if not args.encap_ipv6 else 40
        pps = line_rate_to_ip_pps(l1_rate, ipmtu + ip_ohead)
    elif args.dont_use_tfs:
        ipsec_ohead = ipsec_overhead(gcm, ipmtu, args.encap_ipv6, args.encap_udp)
        pps = line_rate_to_ip_pps(l1_rate, ipmtu + ipsec_ohead)
    else:
        pps = line_rate_to_iptfs_encap_pps(
            l1_rate, ipmtu, iptfs_mtu, gcm, args.cc, args.encap_ipv6, args.encap_udp
        )
    return pps


def get_max_client_rate(c):
    if not c:
        return None
    max_speed = 0
    ports = c.get_acquired_ports()
    if not ports:
        ports = [0, 1]
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

    pps_sum = sum([x["pps"] for x in imix_table])
    avg_ipsize = sum([mps(x["size"]) * x["pps"] for x in imix_table]) / pps_sum
    pps = line_rate_to_pps(args, l1_rate, avg_ipsize, iptfs_mtu)
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
    assert args.user_packet_size

    if args.ipv6_traffic:
        minpkt = 48
    else:
        minpkt = 28

    spread_count = (args.user_packet_size + 1) - minpkt
    avg_ipsize = sum(range(minpkt, args.user_packet_size + 1)) / spread_count
    pps = line_rate_to_pps(args, args.rate, avg_ipsize, args.iptfs_packet_size)
    if args.percentage:
        pps = pps * (args.percentage / 100)

    # if c:
    #     max_speed = get_max_client_rate(c)
    #     max_pps = line_rate_to_ip_pps(max_speed, avg_ipsize)
    #     if pps > max_pps:
    #         max_speed_float = max_speed / 1e9
    #         capacity = 100 * max_pps / pps
    #         logger.warning("%s",
    #           (f"Lowering pps from {pps} to {max_pps} due to client max speed"
    #            f"{max_speed_float}GBps ({capacity:.1f}% of tunnel capacity)"))
    #         pps = max_pps

    table = [
        {
            "size": args.user_packet_size,
            "pps": pps,
            "pg_id": 1,
        }
    ]
    desc = f"Spread (avg: {avg_ipsize}) @ {pps}pps for {args.duration}s"
    return table, pps, avg_ipsize, desc


def get_imix_table(args, c, max_imix_size=1500):
    if args.user_packet_size:
        ipsize = args.user_packet_size
        pps = line_rate_to_pps(args, args.rate, ipsize, args.iptfs_packet_size)
        if args.percentage:
            pps = pps * (args.percentage / 100)

        capacity = 0
        if c:
            max_speed = get_max_client_rate(c)
            max_pps = line_rate_to_ip_pps(max_speed, ipsize)
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
            f"static IP size {ipsize}@{get_human_readable(pps)}pps"
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
            args, imix_table, args.rate, args.iptfs_packet_size, args.percentage, True
        )
        capacity = 0
        if c:
            max_speed = get_max_client_rate(c)
            max_pps = line_rate_to_ip_pps(max_speed, avg_ipsize)
            capacity = 100 * pps / max_pps
        desc = (
            f"imix (avg: {avg_ipsize})@{get_human_readable(pps)}pps "
            f" {capacity:.1f}% of capacity"
        )

    return imix_table, pps, avg_ipsize, desc


def clear_stats(c):
    """Clear all statistics.

    CLear all stats (and pcap drop capture if configured) in trex and vpp hosts
    """
    if c is not None:
        c.clear_stats()


def collect_trex_stats(c, unidir=False):
    stats = c.get_stats()
    stats[0]["rx-missed"] = stats[1]["opackets"] - stats[0]["ipackets"]
    stats[1]["rx-missed"] = stats[0]["opackets"] - stats[1]["ipackets"]
    if unidir:
        stats[0]["rx-missed-pct"] = 0
    else:
        stats[0]["rx-missed-pct"] = (
            100 * (stats[1]["opackets"] - stats[0]["ipackets"]) / stats[1]["opackets"]
        )
    stats[1]["rx-missed-pct"] = (
        100 * (stats[0]["opackets"] - stats[1]["ipackets"]) / stats[0]["opackets"]
    )
    return stats


def check_running(dut):
    return not hasattr(dut, "check_running") or dut.check_running()


def get_active_dut(dutlist):
    a = []
    for dut in dutlist:
        if check_running(dut):
            a.append(dut)
        else:
            logger.warning("%s exited", dut.name)
    return a


def check_active_dut(dutlist):
    active_dutlist = get_active_dut(dutlist)
    if active_dutlist != dutlist:
        for dut in dutlist:
            if dut not in active_dutlist:
                dut.gather_any_core_info()
        raise Exception("Not all DUT are running")


def wait_for_test_done(
    dutlist, c, check_ports, starttime, endtime, beat_callback, beat_time=1
):
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

        # Need to make sure we don't abort b/c of gdb.
        if any(not x.args.gdb and not check_running(x) for x in dutlist):
            logger.info("A VPP has exited")
            logger.info("Stopping traffic on TREX")
            if c:
                c.stop()
            break

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


async def run_trex_cont_test(
    args,
    c,
    dutlist,
    mult,
    get_streams_func,
    imix_table,
    extended_stats=False,
    beat_callback=None,
    beat_time=1,
    modeclass=None,
    statsclass=None,
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

        check_ports = ports[:1] if args.unidirectional else ports
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

    for v in dutlist:
        if v.args.event_log_size and not v.args.event_log_startup:
            v.vppctl("event-logger restart")
            if v.args.event_log_dispatch:
                v.vppctl("elog trace api barrier dispatch")
            elif v.args.event_log_barrier:
                v.vppctl("elog trace api barrier ")

    #
    # Don't bother starting test if a VPP has exited.
    #
    check_active_dut(dutlist)

    # Setup beat callback and end times
    starttime = datetime.datetime.now()
    endtime = starttime + datetime.timedelta(0, duration)

    #
    # Start the traffic
    #

    if c:
        logger.info("Starting TREX: mult: %s duration: %s", str(mult), str(duration))
        c.start(ports=check_ports, mult=mult, duration=duration)

    #
    # wait for active ports done
    #
    wait_for_test_done(
        dutlist, c, check_ports, starttime, endtime, beat_callback, beat_time
    )

    logger.debug("TREX: after wait on traffic")

    #
    # gpz workaround
    # ETFS tests have not waited long enough to collect VPP counters after
    # the test runs, causing reported values to be incorrect (low). Waiting
    # a few seconds here yields the correct values.
    #
    time.sleep(5)

    active_dutlist = get_active_dut(dutlist)

    #
    # Stop event logs and captures.
    #
    # cap_offs = {}
    # dispatch_cap_offs = {}

    async def stop_disruptive(x):
        # if x.args.dispatch_trace:
        #     dispatch_cap_offs[x.host] = x.vppctl("pcap dispatch trace off")
        # if x.args.event_log_size:
        #     x.vppctl("event-logger stop")
        # if args.capture_drops:
        #     cap_offs[x.host] = x.vppctl("pcap trace off")
        # # Terminate the capture now.
        # for server in pcap_servers:
        #     server.stop()
        del x

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

    vstats = None
    # vstats = await asyncio.gather(
    #     *[collect_dut_stats(dut, extended_stats) for vpp in active_dutlist])

    active_dutlist = get_active_dut(active_dutlist)

    #
    # Collect captures and logs that could be distruptive to stats.
    #

    logger.debug("Collecting disruptive stats")
    showrun = []
    for vpp in active_dutlist:
        sr = "RUN: " + vpp.vppctl("show runtime time").replace("\n", "\nRUN: ")
        sr += "\nMAX: " + vpp.vppctl("show runtime time max").replace("\n", "\nMAX: ")
        showrun.append(sr)

    # pcap_files = {}
    # dispatch_pcap_files = {}

    async def collect_disruptive(x):
        # logger.debug("%s: Collecting disruptive stats", x.host)
        # if x.host in cap_offs and "No packets" not in cap_offs[x.host]:
        #     # Grab the pcap file. XXX should go to file named for this test.
        #     pcap = x.get_remote_file("/tmp/vpp-drops.pcap")
        #     pcapfile = os.path.join(g_logdir, f"{x.host}-pcap-drop.pcap")
        #     with open(f"{pcapfile}", "wb") as pcapf:
        #         pcapf.write(pcap)
        #     pcap_files[x.host] = pcapfile
        # if (
        # x.host in dispatch_cap_offs and "No packets" not in dispatch_cap_offs[x.host]
        # ):
        #     # Grab the pcap file. XXX should go to file named for this test.
        #     pcap = x.get_remote_file("/tmp/dispatch.pcap")
        #     pcapfile = os.path.join(g_logdir, f"{x.host}-pcap-dispatch.pcap")
        #     with open(f"{pcapfile}", "wb") as pcapf:
        #         pcapf.write(pcap)
        #     dispatch_pcap_files[x.host] = pcapfile
        # if x.args.event_log_size:
        #     x.save_event_log()
        del x

    # for r in asyncio.as_completed([collect_disruptive(vpp) for vpp in dutlist]):
    #     await r

    results = []
    for vpp in active_dutlist:
        results.append(collect_disruptive(vpp))
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
    for i, sr in enumerate(showrun):
        name = dutlist[i].name
        logger.debug("%s:\n%s", name, sr.replace("\n", f"\n{name}: "))

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
    for _, vpp in enumerate(dutlist):
        logger.info("%s", f"VPP HOST: {vpp.host}:")
        # We do not want bogus way late stats reported!
        # logger.info(vpp.vppctl("show errors"))
        # dump_tun_stats(vpp, *vstats[index][-1][1:])
        # dump_ifstats_one(vpp, vstats[index])
    if args.pause:
        logger.info("%s", f"Pausing after {reason}")
        result = input('Pausing with testbed UP, RETURN to continue, "p" for PDB: ')
        if result.strip().lower() == "p":
            breakpoint()
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

    # for i, dut in enumerate(dutlist):
    #     trx = trex_stats[i]["ipackets"]
    #     vuser_tx = vstats[i][dut.USER_IFINDEX]["/if/tx"]
    #     if trx != vuser_tx:
    #         reason = f"FAILED: dut{i}/trex port{i} vuser_tx: {vuser_tx} != prx: {trx}"
    #         fail_test(args, reason, trex_stats, vstats, dutlist)


def log_packet_counts(dutlist, trex_stats, vstats):
    assert not dutlist or len(dutlist) == 2
    for i, vpp in enumerate(dutlist):
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
        tx = trex_stats[i]["opackets"]
        rx = vstats[i][vpp.USER_IFINDEX]["/if/rx"]
        missed = tx - rx
        if missed:
            pct = abs((missed / tx) * 100)
            # mstr = "missed" if missed > 0 else "extra"
            missed = abs(missed)
            logging.info(
                "%s",
                f"TEST INFO VPP->TREX: {i} tx: {tx} "
                "rx: {rx} {mstr}: {missed} {mstr}-pct: {pct}",
            )
        tx = trex_stats[i]["opackets"]
        rx = vstats[i][vpp.USER_IFINDEX]["/if/rx"]
        missed = tx - rx
        if missed:
            pct = abs((missed / tx) * 100)
            # mstr = "missed" if missed > 0 else "extra"
            missed = abs(missed)
            logging.info(
                "%s",
                f"TEST INFO VPP->TREX: {i} tx: {tx} "
                "rx: {rx} {mstr}: {missed} {mstr}-pct: {pct}",
            )


def finish_test(module_name, args, dutlist, trex, trex_stats, vstats):
    del module_name
    # save_stats(module_name, "trex-stats", trex_stats)
    # save_stats(module_name, "vpp-stats", vstats)

    if trex:
        if args.percentage is None or args.percentage <= 100:
            check_missed(args, trex_stats, vstats, dutlist)

        # logging.debug("TREX Stats:\n%s" % pprint.pformat(trex_stats, indent=4))

        log_packet_counts(dutlist, trex_stats, vstats)

    logging.info("TEST PASSED")

    if args.pause_on_success:
        input("Pausing after test, RETURN to continue")
