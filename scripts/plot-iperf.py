#!/usr/bin/env python3
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# October 2 2023, Christian Hopps <chopps@labn.net>
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

import argparse
import logging
import os
import re
import subprocess
import sys

# matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import numpy as np

# import matplotlib


def do_run(datafile, ax):

    F_MODE = 0
    F_CONFIG = 1
    F_PKTSIZE = 2  # pylint: disable=W0612
    F_RATE = 3
    F_RETRANS = 4
    F_HUMAN_RATE = 5

    filedata = open(datafile, encoding="utf-8").read().splitlines()
    filedata = [x.split(",") for x in filedata if x.strip()]

    data = {}
    for x in filedata:
        if x[1] not in data:
            data[x[1]] = {}
        d = data[x[1]]
        if x[0] not in d:
            d[x[0]] = []
        l = d[x[0]]
        l.append(x[2:5])

    for i, config in enumerate(["encap4-ipv4", "encap6-ipv6"]):
        d = data[config]
        for j, mode in enumerate(["iptfs-policy", "tunnel-policy"]):
            l = d[mode]
            x = [e[0] for e in l]
            y = [float(e[1]) for e in l]
            ax[i].plot(x, y, label=mode)
            ax[i].set_title(config)
        ax[i].legend()

    breakpoint()


def main(*margs):
    parser = argparse.ArgumentParser()
    parser.add_argument("data", help="plot data")
    parser.add_argument("--output", help="save to a file")
    parser.add_argument("--verbose", action="store_true", help="rate to plot")
    args = parser.parse_args(*margs)

    # figsize is in inches.
    # fig, axs = plt.subplots(nrows=len(args.plots) // 2, ncols=1)
    _, axs = plt.subplots(figsize=(16 * 3 / 2, 9 * 3 / 2), nrows=2, ncols=1)
    # fig = plt.figure(figsize=(16, 9))
    do_run(args.data, axs)

    # fig.tight_layout()
    # plt.ylabel("Count")
    # plt.subplots_adjust(left=0, bottom=0, right=1, top=1, wspace=0, hspace=0)
    if args.output:
        plt.savefig(args.output, dpi=300)
    else:
        plt.show()


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        logging.error("Exception from main: %s", ex, exc_info=True)
