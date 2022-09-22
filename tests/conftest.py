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
"""Fixtures and other utilities imported from munet for testing."""
# pylint: disable=wildcard-import,unused-wildcard-import
from munet.testing.fixtures import *  # noqa
from munet.testing.hooks import *  # noqa
from munet.testing.hooks import pytest_addoption as _pytest_addoption


def pytest_addoption(parser):  # pylint: disable=E0102
    parser.addoption(
        "--enable-physical",
        action="store_true",
        help="Enable the physical interface based tests",
    )
    return _pytest_addoption(parser)
