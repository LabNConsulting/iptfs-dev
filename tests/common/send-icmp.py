#!/usr/bin/env python3
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# September 22 2022, Christian Hopps <chopps@labn.net>
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

import argparse
import datetime
import ipaddress
import logging
import socket
import struct
import time

from common.testutil import convert_number, line_rate_to_ip_pps

ICMP_ECHO = 8
ICMP_ECHO_CODE = 0


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true", help="Be verbose")
    parser.add_argument(
        "--rate",
        default="1M",
        help="Send rate in bits-per-second [KMGT suffix accepted]",
    )
    parser.add_argument("remote", help="address to send ICMP packet to")
    args = parser.parse_args()

    dstip = str(ipaddress.ip_address(args.remote))
    dstaddr = (dstip, 1)

    # get a raw socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)

    pktsize = 20 + 8  # 20 IP header + 8 ICMP echo header
    rate = convert_number(args.rate)
    pps = line_rate_to_ip_pps(rate, pktsize)
    tick = 1 / float(pps)

    cksum = 0
    seq = 0
    nexttime = time.clock_gettime(time.CLOCK_MONOTONIC_RAW)
    while True:
        nexttime += tick
        seq += 1
        icmp = struct.pack("!BBHI", ICMP_ECHO, ICMP_ECHO_CODE, cksum, seq)
        s.sendto(icmp, dstaddr)
        now = time.clock_gettime(time.CLOCK_MONOTONIC_RAW)
        if now < nexttime:
            time.sleep(nexttime - now)
        else:
            logging.warning(
                "underrun: late to send by %s ticks", (now - nexttime) / tick
            )


if __name__ == "__main__":
    main()
