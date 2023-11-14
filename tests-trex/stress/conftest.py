# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# January 17 2023, Christian Hopps <chopps@labn.net>
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
"""Add stress test options to CLI."""


def pytest_addoption(parser):  # pylint: disable=E0102
    parser.addoption(
        "--connections",
        type=int,
        help="number of connectoin (really parallel execution) in test",
    )

    parser.addoption(
        "--mode",
        help="'iptfs' or 'tunnel' mode",
    )

    parser.addoption(
        "--rate",
        help="rate to run test at",
    )

    parser.addoption(
        "--pkt-size",
        type=int,
        help="tunnel packet size",
    )

    parser.addoption(
        "--unidir",
        type=int,
        help="Only run in one direction 0 or 1 for direction",
    )

    parser.addoption(
        "--user-pkt-size",
        type=int,
        help="user packet size",
    )
