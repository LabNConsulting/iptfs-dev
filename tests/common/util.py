# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# October 26 2022, Christian Hopps <chopps@labn.net>
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
"General purpose utility functions"
import asyncio
import logging
import os
import re
from datetime import datetime, timedelta
from subprocess import check_output


def myreadline(f):
    buf = ""
    while True:
        # logging.info("READING 1 CHAR")
        c = f.read(1)
        if not c:
            return buf if buf else None
        buf += c
        # logging.info("READ CHAR: '%s'", c)
        if c == "\n":
            return buf


def wait_output(p, regex, timeout=120):
    retry_until = datetime.now() + timedelta(seconds=timeout)
    regex = re.compile(regex)
    while datetime.now() < retry_until:
        line = myreadline(p.stdout)
        if not line:
            assert None, f"EOF waiting for '{regex}'"
        line = line.rstrip()
        if line:
            logging.info("GOT LINE: '%s'", line)
        m = regex.search(line)
        if m:
            return m
    assert None, f"Failed to get output withint {timeout}s"


class Timeout:
    """An object to passively monitor for timeouts."""

    def __init__(self, delta):
        self.started_on = datetime.datetime.now()
        self.expires_on = self.started_on + datetime.timedelta(seconds=delta)

    def elapsed(self):
        elapsed = datetime.datetime.now() - self.started_on
        return elapsed.total_seconds()

    def is_expired(self):
        return datetime.datetime.now() > self.expires_on


def chunkit(lst, chunk):
    for i in range(0, len(lst), chunk):
        yield lst[i : i + chunk]


def get_intf_stats(intf):
    try:
        output = check_output(f"ip -s link show {intf}", shell=True, text=True).strip()
        lines = output.split("\n")
        rxstats = [int(x) for x in lines[3].strip().split()]
        txstats = [int(x) for x in lines[5].strip().split()]
        return rxstats[1], txstats[1], rxstats[2:-1], txstats[2:-1]
    except Exception as error:
        logging.error("Got error getting stats: %s", error)
        raise


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


def start_profile(unet, hostname, tval):
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
        tval,
    ]
    host = unet.hosts[hostname]
    host.cmd_raises("sysctl -w kernel.perf_cpu_time_max_percent=75")
    logging.info("Starting perf-profile on %s for %s", hostname, tval)

    p = host.popen(perfargs, use_pty=True, start_new_session=True)
    p.host = host
    return p


def stop_profile(p, filebase="perf.data"):
    try:
        try:
            # logging.info("signaling perf to exit")
            # p.send_signal(signal.SIGTERM)
            logging.info("waiting for perf to exit")
            o, e = p.communicate(timeout=5.0)
            o = "\nerror:\n" + o if o else ""
            e = "\nerror:\n" + e if e else ""
            logging.info(
                "perf rc: %s%s%s",
                p.returncode,
                o,
                e,
            )
            pdpath = os.path.join(p.host.rundir, filebase)
            p.host.cmd_raises(["/bin/cat", "/tmp/perf.data"], stdout=open(pdpath, "wb"))
            p = None
        except TimeoutError:
            logging.warning("perf didn't finish after signal rc: %s", p.returncode)
            raise
        except Exception as error:
            logging.warning(
                "unexpected error while waiting for perf: %s", error, exc_info=True
            )
    finally:
        if p is not None:
            logging.info("terminating perf")
            p.terminate()
            try:
                _, e = p.communicate(timeout=2.0)
                logging.warning("perf rc: %s error: %s", p.returncode, e)
            except TimeoutError:
                logging.warning(
                    "perf didn't finish after terminate rc: %s", p.returncode
                )
