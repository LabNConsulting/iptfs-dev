# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# February 9 2022, Christian Hopps <chopps@labn.net>
#
# Copyright 2022, LabN Consulting, L.L.C.
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
# import asyncio
import logging
import time

import pytest

# from munet.parser import build_topology

# All tests are coroutines
pytestmark = pytest.mark.asyncio


async def _test_console(r, cmd, use_pty, will_echo=False):
    time.sleep(1)
    repl = await r.console(
        cmd, user="root", use_pty=use_pty, trace=True, will_echo=will_echo, ns_only=True
    )
    return repl


async def test_console_pty(unet_share):
    "Test pty inside the VM"
    unet = unet_share
    r1 = unet.hosts["r1"]
    cmd = [
        "socat",
        "/dev/stdin,rawer,echo=0,icanon=0",
        f"unix-connect:{r1.rundir}/s/console",
    ]
    repl = await _test_console(r1, cmd, use_pty=True, will_echo=True)

    output = repl.cmd_raises("ls --color=never -1 /sys")
    logging.debug("'ls /sys' output: '%s'", output)
    expect_ls = "\n".join(
        [
            "block",
            "bus",
            "class",
            "dev",
            "devices",
            "firmware",
            "fs",
            "kernel",
            "module",
            "power",
        ]
    )
    assert output == expect_ls
    logging.debug("'ls --color=never -1 /sys' output: %s", output)
    output = repl.cmd_raises("echo $?")
    logging.debug("'echo $?' output: %s", output)


async def test_console_piped(unet_share):
    "Test inside the VM"
    unet = unet_share
    r1 = unet.hosts["r1"]
    cmd = ["socat", "-", f"unix-connect:{r1.rundir}/s/console"]
    repl = await _test_console(r1, cmd, use_pty=False, will_echo=True)

    output = repl.cmd_raises("ls -1 --color=never /sys")
    logging.debug("'ls /sys' output: '%s'", output)
    expect_ls = "\n".join(
        [
            "block",
            "bus",
            "class",
            "dev",
            "devices",
            "firmware",
            "fs",
            "kernel",
            "module",
            "power",
        ]
    )
    assert output == expect_ls

    output = repl.cmd_raises("echo $?")
    logging.debug("'echo $?' output: %s", output)
