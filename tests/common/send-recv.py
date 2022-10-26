#!/usr/bin/env python3
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# September 24 2022, Christian Hopps <chopps@labn.net>
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
import logging
import socket

from common.util import convert_number, get_human_readable

BLOCKSIZE = 2**20


def run_server(port=6201):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * BLOCKSIZE)
        s.bind(("0.0.0.0", port))
        logging.info("recv: server listening on port %s", port)
        s.listen()
        while True:
            conn, addr = s.accept()
            with conn:
                logging.info("recv: connection from %s", addr)
                count = 0
                while True:
                    data = conn.recv(BLOCKSIZE)
                    if not data:
                        break
                    count += len(data)
                    logging.debug("recv: received %s bytes", len(data))
                logging.info(
                    "recv: connection closed received %s bytes",
                    get_human_readable(count),
                )


def run_client(remote, port, length):
    blocksize = BLOCKSIZE
    block = bytearray(blocksize)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, BLOCKSIZE)

    # logging.info(
    #     "TCP MSS started as %s", s.getsockopt(socket.SOL_TCP, socket.TCP_MAXSEG)
    # )
    # s.setsockopt(socket.SOL_TCP, socket.TCP_MAXSEG, 1300)
    # logging.info(
    #     "TCP MSS changed to %s", s.getsockopt(socket.SOL_TCP, socket.TCP_MAXSEG)
    # )

    # s.connect((remote, port))

    # s.setsockopt(socket.SOL_TCP, socket.TCP_MAXSEG, 1400)
    # logging.info(
    #     "TCP MSS changed to %s", s.getsockopt(socket.SOL_TCP, socket.TCP_MAXSEG)
    # )

    logging.info("send: connected to %s port %s sending %s bytes", remote, port, length)
    count = 0
    nbatch = 0
    while count < length:
        if length - count < blocksize:
            l = s.send(block[: length - count])
        else:
            l = s.send(block)
        if not l:
            break
        nbatch += 1
        logging.debug("send: sent %s of %s bytes", l, blocksize)
        count += l
    logging.info("send: done sending %s bytes in %d batches", count, nbatch)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", default="10M", help="Send this many bytes to server")
    parser.add_argument("-p", type=int, default=6201, help="TCP port")
    parser.add_argument("-s", action="store_true", help="TCP server mode")
    parser.add_argument("-v", action="store_true", help="Be verbose")
    parser.add_argument("remote", nargs="?", help="Remote server to connect to")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.v else logging.INFO)
    if args.s:
        run_server(args.p)
    else:
        run_client(args.remote, args.p, convert_number(args.l))


if __name__ == "__main__":
    main()
