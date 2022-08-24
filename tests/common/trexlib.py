# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# July 5 2022, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2020-2022, LabN Consulting, L.L.C.
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
"""
A module of utility functions for authoring Trex tests.
"""
import collections
import ipaddress
import logging

# from trex_stl_lib.api import STLVM
from trex_stl_lib.api import (
    ICMP,
    IP,
    UDP,
    CTRexVmInsFixHwCs,
    Dot1Q,
    Ether,
    ICMPv6EchoRequest,
    IPv6,
    STLFlowStats,
    STLPktBuilder,
    STLScVmRaw,
    STLStream,
    STLTXCont,
    STLTXSingleBurst,
    STLVmFixChecksumHw,
    STLVmFixIpv4,
    STLVmFlowVar,
    STLVmTrimPktSize,
    STLVmWrFlowVar,
)

logger = logging.getLogger(__name__)


def ipv4_ipv6(ip):
    pfx = ipaddress.IPv6Address("2100::").packed[0 : 16 - 4]
    return ipaddress.IPv6Address(pfx + ipaddress.IPv4Address(ip).packed)


# Create IP base packet
def create_ip_pkt(src, dst, vlan, ipv6):
    if vlan is not None:
        base_pkt = Ether() / Dot1Q(vlan=vlan)
    else:
        base_pkt = Ether()
    if ipv6:
        base_pkt /= IPv6(src=ipv4_ipv6(src), dst=ipv4_ipv6(dst))
    else:
        base_pkt /= IP(src=src, dst=dst)
    return base_pkt


# Create a padded packet
def create_udp_pkt(size, src, dst, vlan, ipv6):
    """Create an IP/UDP packet of a given size (add padding)"""
    base_pkt = create_ip_pkt(src, dst, vlan, ipv6) / UDP(sport=0x5555, dport=0xAAAA)
    pad = max(0, size + 14 - len(base_pkt)) * "x"  # 46 - 28 = 18
    return base_pkt / pad


# Create a dynamic padded packet
def create_udp_pkt_builder(
    vm, size, src="16.0.0.1", dst="48.0.0.1", vlan=None, ipv6=False
):
    """Create an IP/UDP packet builder of a given size (add padding)"""
    return STLPktBuilder(pkt=create_udp_pkt(size, src, dst, vlan, ipv6), vm=vm)


# Create a padded packet
def create_icmp_pkt(size, src, dst, vlan, ipv6):
    """Create an IPCMP or ICMPv6 packet of a given size (add padding)"""
    if ipv6:
        base_pkt = create_ip_pkt(src, dst, vlan, ipv6) / ICMPv6EchoRequest()
    else:
        base_pkt = create_ip_pkt(src, dst, vlan, ipv6) / ICMP(type=8)
    pad = max(0, size + 14 - len(base_pkt)) * "x"  # 46 - 28 = 18
    return base_pkt / pad


# Create a dynamic padded packet
def create_icmp_pkt_builder(
    vm, size, src="16.0.0.1", dst="48.0.0.1", vlan=None, ipv6=False
):
    """Create an IP/UDP packet builder of a given size (add padding)"""
    return STLPktBuilder(
        pkt=create_icmp_pkt(size, src, dst, vlan=vlan, ipv6=ipv6), vm=vm
    )


def modeargs(imix_table_ent):
    """A filter for STLTXMode constructor arguments from an imix_table entry"""
    copykeys = ["total_pkts", "pkts_per_burst", "ibg", "count"]
    args = {}
    for key in copykeys:
        if key in imix_table_ent:
            args[key] = imix_table_ent[key]
    for key in "pps", "bps_L1", "percentage", "bps_L2":
        if key in imix_table_ent:
            args[key] = imix_table_ent[key]
            break
    else:
        args["pps"] = 1
    return args


def _get_dynamic_streams(
    direction,
    imix_table,
    op,
    modeclass,
    statsclass,
    ipv6=False,
    value_list=None,
    multi_addr=False,
):
    """A Function that will return a stream of packets of variable size from 40
    bytes up to the size given in the imix_table. The stream is either
    sequentially increasing in size, or random (given by the "op" arg). Note for
    size 40-46 the actual transmitted bytes is the same as the frame is padded,
    however the inner IP length is increasing
    """
    if modeclass is None:
        modeclass = STLTXCont
    if statsclass is None:
        statsclass = STLFlowStats

    src = {"start": "16.0.0.1", "end": "16.0.0.254"}
    dst = {"start": "48.0.0.1", "end": "48.0.0.254"}
    if direction == 1:
        src, dst = dst, src
    assert len(imix_table) == 1
    max_size = imix_table[0]["size"]
    if ipv6:
        min_pkt = Ether() / IPv6() / UDP()
    else:
        min_pkt = Ether() / IP() / UDP()
    base_pkt = create_udp_pkt(
        max_size, src["start"], dst["start"], vlan=None, ipv6=ipv6
    )

    # Create a field engine to modify the base packet

    ops = []

    # fv_walk is in ethernet sizes.
    # We are counting on being able to set this below 60 octets below to create small
    # UDP packets,
    # XXX Need to double check what TREX is actually putting out there! :)

    if value_list is not None:
        # XXX Move this to the caller
        add_counter = True
        ops.append(STLVmFlowVar(name="fv_walk", value_list=value_list, size=2, op=op))
    else:
        # XXX Move this to the caller
        add_counter = False
        min_len = len(min_pkt)
        if add_counter:
            min_len += 4
        ops.append(
            STLVmFlowVar(
                name="fv_walk",
                min_value=min_len,
                max_value=len(base_pkt),
                size=2,
                step=1,
                op=op,
            )
        )
    if add_counter:
        ops.extend(
            [
                STLVmFlowVar(
                    name="counter", min_value=0, max_value=0xFFFFFFFF, size=4, op="inc"
                ),
                STLVmWrFlowVar(fv_name="counter", pkt_offset=len(min_pkt)),
            ]
        )  # just past the UDP heade

    if ipv6:
        trimlen = len(Ether() / IPv6())
        ops.extend(
            [
                STLVmTrimPktSize("fv_walk"),  # total packet size
                STLVmWrFlowVar(
                    fv_name="fv_walk", pkt_offset="IPv6.plen", add_val=-trimlen
                ),  # fix ip len
                STLVmWrFlowVar(
                    fv_name="fv_walk", pkt_offset="UDP.len", add_val=-trimlen
                ),  # fix udp len
            ]
        )
    else:
        ops.extend(
            [
                STLVmTrimPktSize("fv_walk"),  # total packet size
                STLVmWrFlowVar(
                    fv_name="fv_walk", pkt_offset="IP.len", add_val=-len(Ether())
                ),  # fix ip len
                STLVmWrFlowVar(
                    fv_name="fv_walk",
                    pkt_offset="UDP.len",
                    add_val=-len(Ether() / IP()),
                ),  # fix udp len
            ]
        )

    if multi_addr:
        assert not ipv6
        ops.extend(
            [
                STLVmFlowVar(
                    name="src",
                    min_value=src["start"],
                    max_value=src["end"],
                    size=4,
                    op="inc",
                ),
                STLVmFlowVar(
                    name="dst",
                    min_value=dst["start"],
                    max_value=dst["end"],
                    size=4,
                    op="inc",
                ),
                STLVmWrFlowVar(fv_name="src", pkt_offset="IP.src"),
                STLVmWrFlowVar(fv_name="dst", pkt_offset="IP.dst"),
            ]
        )

    if ipv6:
        # forget the cksum for now
        ops.extend(
            [
                STLVmFixChecksumHw(
                    l3_offset=14,
                    l4_offset=trimlen,
                    l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP,
                ),
                # STLVmFixIpv4(offset="IP"),  # fix checksum
            ]
        )
    else:
        ops.extend(
            [
                STLVmFixChecksumHw(
                    l3_offset="IP",
                    l4_offset="UDP",
                    l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP,
                ),
                # STLVmFixIpv4(offset="IP"),  # fix checksum
            ]
        )

    vm = STLScVmRaw(ops)

    return [
        STLStream(
            packet=create_udp_pkt_builder(
                vm, max_size, src["start"], dst["start"], ipv6=ipv6
            ),
            random_seed=0x1234,
            mode=modeclass(**modeargs(x)),
        )
        for x in imix_table
    ]


def get_dynamic_imix_stream(
    direction, imix_table, modeclass=None, statsclass=None, ipv6=False
):
    value_list = [60, 590, 60, 60, 590, 60, 590, 60, 590, 60, 1514, 60]
    return _get_dynamic_streams(
        direction,
        imix_table,
        "inc",
        modeclass,
        statsclass,
        ipv6=ipv6,
        value_list=value_list,
    )


def get_random_size_streams(
    direction, imix_table, modeclass=None, statsclass=None, ipv6=False
):
    """A Function that will return a stream of packets of variable size from 64
    bytes up to the size given in the imix_table. The sizes of the packets are
    random.
    """
    return _get_dynamic_streams(
        direction, imix_table, "random", modeclass, statsclass, ipv6=ipv6
    )


def get_sequential_size_streams(
    direction, imix_table, modeclass=None, statsclass=None, ipv6=False
):
    """A Function that will return a stream of packets of variable size from 64
    bytes up to the size given in the imix_table. The sizes of the packets are
    random.
    """
    return _get_dynamic_streams(
        direction, imix_table, "inc", modeclass, statsclass, ipv6=ipv6
    )


def get_sequential_size_iprange_streams(
    direction, imix_table, modeclass=None, statsclass=None, ipv6=False
):
    """A Function that will return a stream of packets of variable size from 64
    bytes up to the size given in the imix_table. The sizes of the packets are
    random.
    """
    return _get_dynamic_streams(
        direction, imix_table, "inc", modeclass, statsclass, ipv6=ipv6, multi_addr=True
    )


def get_static_streams_simple(
    direction, imix_table, modeclass=None, statsclass=None, ipv6=False, nstreams=1
):
    """A Function that will return a stream of packets of static size as given by
    the size in the imix_table.
    """
    if modeclass is None:
        modeclass = STLTXCont
    if statsclass is None:
        statsclass = STLFlowStats

    streams = []
    netinc = 256 // nstreams
    last = 0
    for i in range(nstreams):
        psinc = i % netinc
        streams.append(
            {
                "src": f"16.0.0.{last + psinc + 1}",
                "dst": f"48.0.0.{last + psinc + 1}",
            }
        )
        last += netinc

    streams = [dict(x) for x in streams]

    if direction == 1:
        for x in streams:
            x["src"], x["dst"] = x["dst"], x["src"]

    # create streams based on the imix_table entries
    # For each connection vm, create a stream for each imix_table entry.
    tstreams = []
    for x in imix_table:
        for i in range(nstreams):
            src = streams[i]["src"]
            dst = streams[i]["dst"]
            s = STLStream(
                isg=x["isg"] if "isg" in x else 0,
                # packet=create_udp_pkt_builder(None, x["size"], src=src, dst=dst),
                packet=create_icmp_pkt_builder(
                    None, x["size"], src=src, dst=dst, ipv6=ipv6
                ),
                mode=modeclass(**modeargs(x)),
                flow_stats=statsclass(x["pg_id"] + i * 100)
                if ("pg_id" in x) and (not direction)
                else None,
            )

            tstreams.append(s)
    return tstreams


def get_static_streams(
    direction,
    imix_table,
    modeclass=None,
    statsclass=None,
    ipv6=False,
    nstreams=1,
    vlan_per_stream=False,
):
    """A Function that will return a stream of packets of static size as given by
    the size in the imix_table.
    """
    # debug - delete me
    logger.debug("gpz debug: get_static_streams entry")

    if modeclass is None:
        modeclass = STLTXCont
    if statsclass is None:
        statsclass = STLFlowStats

    streams = []
    netinc = 256 // nstreams
    last = 0
    for i in range(nstreams):
        s = {
            "src": {
                "start": f"16.0.0.{last + 1}",
                "end": f"16.0.0.{last + netinc - 2}",
            },
            "dst": {
                "start": f"48.0.0.{last + 1}",
                "end": f"48.0.0.{last + netinc - 2}",
            },
        }
        if vlan_per_stream:
            s["vlan"] = 100 + i
        else:
            s["vlan"] = None  # avoid need for conditional below
        streams.append(s)
        last += netinc

    streams = [dict(x) for x in streams]

    if direction == 1:
        for x in streams:
            x["src"], x["dst"] = x["dst"], x["src"]

    # # Create a field engine to modify the base packet
    # vm = STLVM()
    # # define two vars (src and dst)
    # vm.var(name="src", min_value=src['start'], max_value=src['end'], size=4, op="inc")
    # vm.var(name="dst", min_value=dst['start'], max_value=dst['end'], size=4, op="inc")
    # # write them into the packet
    # vm.write(fv_name="src", pkt_offset="IP.src")
    # vm.write(fv_name="dst", pkt_offset="IP.dst")
    # # and fix checksum
    # vm.fix_chksum()

    logger.debug("gpz debug: get_static_streams about to create field engine")

    # Create a field engine to modify the base packet
    # Each connection gets a VM sending to the correct IP range.
    vms = []
    for i in range(nstreams):
        src = streams[i]["src"]
        dst = streams[i]["dst"]
        vms.append(
            STLScVmRaw(
                [
                    STLVmFlowVar(
                        name=f"src-{i}",
                        min_value=src["start"],
                        max_value=src["end"],
                        size=4,
                        op="inc",
                    ),
                    STLVmFlowVar(
                        name=f"dst-{i}",
                        min_value=dst["start"],
                        max_value=dst["end"],
                        size=4,
                        op="inc",
                    ),
                    STLVmWrFlowVar(fv_name=f"src-{i}", pkt_offset="IP.src"),
                    STLVmWrFlowVar(fv_name=f"dst-{i}", pkt_offset="IP.dst"),
                    # # Only works with HW support, may need to make optional
                    # STLVmFixChecksumHw(
                    #     l3_offset="IP",
                    #     l4_offset="UDP",
                    #     l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP,
                    # ),
                    STLVmFixIpv4(offset="IP"),  # fix checksum
                ],
                # split_by_field="ip_src",
                # cache_size=netinc - 2,
            )
        )

    logger.debug("gpz debug: get_static_streams about to create streams")

    # create streams based on the imix_table entries
    # For each connection vm, create a stream for each imix_table entry.
    tstreams = []
    for x in imix_table:
        for vmi, vm in enumerate(vms):
            # could be None
            vlan = streams[vmi]["vlan"]

            logger.debug("gpz debug: get_static_streams vlan={vlan}")

            s = STLStream(
                isg=x["isg"] if "isg" in x else 0,
                packet=create_udp_pkt_builder(vm, x["size"], vlan=vlan, ipv6=ipv6),
                # packet=create_udp_pkt_builder(
                #     vm if "pg_id" not in x or direction else None, x["size"]
                # ),
                mode=modeclass(**modeargs(x)),
                flow_stats=statsclass(x["pg_id"] + vmi * 100)
                if ("pg_id" in x) and (not direction)
                else None,
            )

            tstreams.append(s)
    logger.debug("gpz debug: get_static_streams about returning")
    return tstreams


def get_static_streams_seqnum(
    direction, imix_table, modeclass=None, statsclass=None, ipv6=False, nstreams=1
):
    """A Function that will return a stream of packets of static size as given by
    the size in the imix_table.
    """
    if statsclass is None:
        statsclass = STLFlowStats

    straddrs = []
    netinc = 256 // nstreams
    last = 0
    for i in range(nstreams):
        psinc = i % netinc
        straddrs.append(
            {
                "src": f"16.0.0.{last + psinc + 1}",
                "dst": f"48.0.0.{last + psinc + 1}",
            }
        )
        last += netinc

    if direction == 1:
        for x in straddrs:
            x["src"], x["dst"] = x["dst"], x["src"]

    # Create a field engine to modify the base packet
    vms = []

    if ipv6:
        assert False, "ipv6 not supported yet"
    else:
        for i in range(nstreams):
            vms.append(
                STLScVmRaw(
                    [
                        STLVmFlowVar(
                            name="seq", min_value=0, max_value=65535, size=2, op="inc"
                        ),
                        STLVmWrFlowVar(fv_name="seq", pkt_offset="ICMP.seq"),
                        STLVmFixIpv4(offset="IP"),  # fix checksum
                    ]
                )
            )

    # See if we are sending packets in bursts
    streams = []

    for i, imix_entry in enumerate(imix_table):
        for vmi, vm in enumerate(vms):
            src = straddrs[vmi]["src"]
            dst = straddrs[vmi]["dst"]

            # Make a copy of x so we can modify it.
            x = dict(imix_entry)

            if "impulses" in x and x["impulses"]:
                mc = modeclass if modeclass is not None else STLTXSingleBurst
                assert modeclass is not STLTXCont

                impulses = x["impulses"]
                if isinstance(impulses, collections.Iterable):
                    impdur = None
                    x["total_pkts"] = int(impulses[0])
                else:
                    impdur = x["duration"] / (impulses * 2)
                    x["total_pkts"] = int(x["pps"] * impdur)

                # XXX We probably want to offset each stream for each connection to
                # allow for impulses on all streams

                # If we do impulses on a single stream and idle the others.
                # if not vmi:

                if True:  # pylint: disable=W0125
                    del x["duration"]
                    del x["impulses"]

                    # Offset impulse bursts if they are regular timed
                    if impdur is None:
                        offset = 0
                    else:
                        offset = vmi * (impdur / (nstreams * 4))

                    if offset:
                        save_x = x["total_pkts"]
                        x["total_pkts"] = int(x["pps"] * offset)
                        streams.append(
                            STLStream(
                                name=f"S{i}_${vmi}_off_start_delay",
                                isg=x["isg"] if "isg" in x else 0,
                                packet=create_icmp_pkt_builder(
                                    vm, x["size"], src=src, dst=dst, ipv6=ipv6
                                ),
                                dummy_stream=True,
                                mode=mc(**modeargs(x)),
                                next=f"S{i}_{vmi}_on",
                            )
                        )
                        x["total_pkts"] = save_x

                    streams.append(
                        STLStream(
                            self_start=not offset,
                            name=f"S{i}_{vmi}_on",
                            isg=x["isg"] if "isg" in x else 0,
                            packet=create_icmp_pkt_builder(
                                vm, x["size"], src=src, dst=dst, ipv6=ipv6
                            ),
                            mode=mc(**modeargs(x)),
                            flow_stats=statsclass(x["pg_id"])
                            if "pg_id" in x and not direction
                            else None,
                            next=f"S{i}_{vmi}_off",
                        )
                    )

                    # The next stream starts immediately after sending the last packet
                    # from the previous stream, so instead of trying to calculate the
                    # correct inter-stream-gap, just add an extra packet to the delay.
                    if isinstance(impulses, collections.Iterable):
                        x["total_pkts"] = int(impulses[1]) + 1
                    else:
                        x["total_pkts"] += 1
                    streams.append(
                        STLStream(
                            self_start=False,
                            name=f"S{i}_{vmi}_off",
                            isg=x["isg"] if "isg" in x else 0,
                            packet=create_icmp_pkt_builder(
                                vm, x["size"], src=src, dst=dst, ipv6=ipv6
                            ),
                            dummy_stream=True,
                            mode=mc(**modeargs(x)),
                            next=f"S{i}_{vmi}_on",
                        )
                    )
                else:
                    # Just have a dummy stream do nothing to look for timing affects.
                    if isinstance(impulses, collections.Iterable):
                        x["total_pkts"] += int(impulses[1]) + 1
                    else:
                        x["total_pkts"] *= 2
                        x["total_pkts"] += 1

                    del x["duration"]
                    del x["impulses"]

                    streams.append(
                        STLStream(
                            name=f"S{i}_${vmi}_off",
                            isg=x["isg"] if "isg" in x else 0,
                            packet=create_icmp_pkt_builder(
                                vm, x["size"], src=src, dst=dst, ipv6=ipv6
                            ),
                            dummy_stream=True,
                            mode=mc(**modeargs(x)),
                        )
                    )

            else:
                mc = modeclass if modeclass is not None else STLTXCont
                streams.append(
                    STLStream(
                        isg=x["isg"] if "isg" in x else 0,
                        packet=create_icmp_pkt_builder(
                            vm, x["size"], src=src, dst=dst, ipv6=ipv6
                        ),
                        mode=mc(**modeargs(x)),
                        flow_stats=statsclass(x["pg_id"])
                        if "pg_id" in x and not direction
                        else None,
                    )
                )
    return streams
