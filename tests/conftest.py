# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# February 9 2022, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2022, LabN Consulting, L.L.C
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
# pylint: disable=wildcard-import,unused-wildcard-import
# pylint: disable=wrong-import-position
"""Fixtures and other utilities imported from munet for testing."""

import os
import time

from munet.base import Commander, proc_error
from munet.testing.fixtures import *  # noqa
from munet.testing.hooks import *  # noqa
from munet.testing.hooks import pytest_addoption as _pytest_addoption
from munet.testing.hooks import pytest_configure as _pytest_configure


def pytest_addoption(parser):  # pylint: disable=E0102
    parser.addoption(
        "--enable-ipv6",
        action="store_true",
        help="Enable IPv6 testing",
    )

    parser.addoption(
        "--enable-physical",
        action="store_true",
        help="Enable the physical interface based tests",
    )

    parser.addoption(
        "--iptfs-opts",
        help="options for iptfs",
    )

    parser.addoption(
        "--profile",
        action="store_true",
        help="Enable profiling if supported by test",
    )

    parser.addoption(
        "--tracing",
        action="store_true",
        help="Enable tracing if supported by test",
    )

    rundir_help = "directory for running in and log files"
    parser.addini("rundir", rundir_help, default="/tmp/unet-test")
    parser.addoption("--rundir", metavar="DIR", help=rundir_help)

    return _pytest_addoption(parser)


def pytest_configure(config):

    rdir = config.option.rundir
    if not rdir:
        rdir = config.getini("rundir")
    if not rdir:
        rdir = "/tmp/unet-test"
    config.option.rundir = rdir

    if not config.getoption("--junitxml"):
        config.option.xmlpath = os.path.join(rdir, "unet-test.xml")
    xmlpath = config.option.xmlpath

    # Save an existing unet-test.xml
    if os.path.exists(xmlpath):
        fmtime = time.localtime(os.path.getmtime(xmlpath))
        suffix = "-" + time.strftime("%Y%m%d%H%M%S", fmtime)
        commander = Commander("pytest")
        mv_path = commander.get_exec_path("mv")
        commander.cmd_status([mv_path, xmlpath, xmlpath + suffix])

    return _pytest_configure(config)


# This still doesn't work and
# def pytest_collection_finish(session):
#     found = False
#     for item in session.items:
#         if "stress" in str(item.path):
#             logging.warning("Found stress test '%s', modifying sys.path", item.path)
#             found = True
#             break
#     if found:
#         # So gross.. but trex plays stupid games with embedded pkgs and path
#         SRCDIR = os.path.dirname(os.path.abspath(__file__))
#         trexlib = os.path.join(SRCDIR, "external_libs")
#         scapydir = glob.glob(trexlib + "/scapy*")[0]
#         sys.path[0:0] = [scapydir]
