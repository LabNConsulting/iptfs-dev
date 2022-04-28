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


async def _test_console(unet, cmd, use_pty, noecho=False):
    r1 = unet.hosts["r1"]
    time.sleep(1)
    repl = await r1.console(
        cmd, user="root", use_pty=use_pty, trace=True, noecho=noecho
    )
    return repl


async def test_console_pty(unet):
    "Test pty inside the VM"
    cmd = [
        "socat",
        "/dev/stdin,rawer,echo=0,icanon=0",
        "unix-connect:/tmp/qemu-sock/console",
    ]
    repl = await _test_console(unet, cmd, use_pty=True)

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


async def test_console_piped(unet):
    "Test inside the VM"
    cmd = ["socat", "-", "unix-connect:/tmp/qemu-sock/console"]
    repl = await _test_console(unet, cmd, use_pty=False)

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


async def test_console_namespace_piped(unet):
    "Test inside the namespace but not in the VM"
    repl = await _test_console(unet, ["/bin/sh", "-si"], use_pty=False, noecho=True)
    output = repl.cmd_raises("ls --color=never -1 s")
    expect_ls = "\n".join(
        [
            "console",
            "console2",
            "gdbserver",
            "monitor",
            "replcon",
        ]
    )
    logging.debug("'ls' output: %s", output)
    logging.debug("'ls' expected output: %s", expect_ls)
    assert output == expect_ls

    output = repl.cmd_raises("env")
    logging.debug("'env' output: %s", output)

    output = repl.cmd_raises("echo $?")
    logging.debug("'echo $?' output: %s", output)


async def test_console_namespace_pty(unet):
    "Test pty inside the namespace but not in the VM"
    repl = await _test_console(unet, ["/bin/sh"], use_pty=True, noecho=True)
    output = repl.cmd_raises("ls --color=never -1 s")
    logging.debug("'ls' output: %s", output)
    expect_ls = "\n".join(
        [
            "console",
            "console2",
            "gdbserver",
            "monitor",
            "replcon",
        ]
    )
    assert output == expect_ls
    output = repl.cmd_raises("echo $?")
    logging.debug("'echo $?' output: %s", output)
