# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# July 14 2019, Christian Hopps <chopps@labn.net>
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
import logging
import socket
import struct
from functools import partial

from scapy.compat import orb, raw
from scapy.config import conf
from scapy.data import IP_PROTOS
from scapy.fields import (
    FlagsField,
    PacketListField,
    ShortField,
    StrLenField,
    XByteField,
)
from scapy.layers import ipsec
from scapy.layers.inet import ICMP, IP
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import CRYPT_ALGOS, ESP, _ESPPlain, split_for_transport
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw, bind_layers

IPPROTO_IPTFS = 144
IP_PROTOS["iptfs"] = IPPROTO_IPTFS

logger = logging.getLogger("scapy_iptfs")

# fix bug in scapy
CRYPT_ALGOS["AES-GCM"].block_size = 1

# This causes NAT and reassembly unit-tests to fail.
# conf.debug_dissector = True


def sizeof(x):
    return len(x)


# This was way too hard to figure out. :)
class AllPadField(StrLenField):
    def getfield(self, pkt, s):
        slen = len(s)
        return s[slen:], self.m2i(pkt, s[:slen])

    def i2repr(self, pkt, x):
        return "PadBytes({})".format(len(x))


class IPTFSPad(Packet):
    name = "IPTFSPad"
    fields_desc = [XByteField("zerotype", 0), AllPadField("pad", "")]


def fraglen_from(*args):
    # B/c python foo[:fraglen] works even when fraglen > len(foo)
    # this handles a block_offset being beyond the end of the packet.
    return args[0].fraglen


class IPTFSFrag(Packet):
    __slots__ = ["fraglen"]

    fields_desc = [StrLenField("frag", None, length_from=fraglen_from)]

    def __init__(self, *args, **kwargs):
        if "fraglen" in kwargs:
            self.fraglen = kwargs["fraglen"]
            del kwargs["fraglen"]
        super().__init__(self, *args, **kwargs)

    def default_payload_class(self, payload):
        # Return padding here so PacketFieldList re-uses it.
        return conf.padding_layer


class IPTFSEndFrag(IPTFSFrag):
    pass


class IPTFSIPFrag(IPTFSFrag):
    pass


class IPTFSIPv6Frag(IPTFSFrag):
    pass


def get_frag_class_and_len(data):
    """
    Return the class and possibly the packet length if present in the data fragment.
    """
    # Check for trailing fragment
    dlen = len(data)
    t = orb(data[0]) & 0xF0
    if t == 0x40:
        if dlen < 4:
            return IP, None
        return IP, (orb(data[2]) << 8) + orb(data[3])
    if t == 0x60:
        if dlen < 6:
            return IPv6, None
        return IPv6, (orb(data[4]) << 8) + orb(data[5]) + sizeof(IPv6())
    return Raw, None


def iptfs_decap_pkt_with_frags(ppkt, pkts, curpkt, data):  # pylint: disable=R0911
    # logger.critical("iptfs_decap_pkt: pptype %s lens: %d %d",
    # str(type(data)), len(curpkt) if curpkt is not None else 0, len(data))
    # Check for type and frag here.
    del pkts
    if not curpkt and ppkt.block_offset:
        # First datablock in packet with offset so start with the fragment.
        return partial(IPTFSEndFrag, fraglen=ppkt.block_offset)

    assert data
    t = orb(data[0]) & 0xF0
    if t == 0:
        return IPTFSPad
    if t in [0x40, 0x60]:
        # Check for trailing fragment
        dlen = len(data)

        extlen = 0
        if t == 0x40:
            fcls = IPTFSIPFrag
            cls = IP
            loff = 2
        else:
            fcls = IPTFSIPv6Frag
            cls = IPv6
            loff = 4
            extlen += len(IPv6())
        if dlen < loff + 2:
            return partial(fcls, fraglen=dlen)
        iplen = (orb(data[loff]) << 8) + orb(data[loff + 1]) + extlen
        if iplen > dlen:
            return partial(fcls, fraglen=dlen)
        return cls
    return conf.raw_layer


def _iptfs_decap_pkt_with_frags(ppkt, pkts, curpkt, data):
    # logger.critical("iptfs_decap_pkt: pptype %s lens: %d %d",
    # str(type(data)), len(curpkt) if curpkt is not None else 0, len(data))
    # Check for type and frag here.
    del pkts
    if not curpkt and ppkt.block_offset:
        # First datablock in packet with offset so start with the fragment.
        return partial(IPTFSEndFrag, fraglen=ppkt.block_offset)

    assert data
    t = orb(data[0]) & 0xF0
    if t == 0:
        return IPTFSPad
    if t in [0x40, 0x60]:
        # Check for trailing fragment
        dlen = len(data)
        if dlen < 20:
            return partial(IPTFSFrag, fraglen=dlen)

        if t == 0x40:
            iplen = (orb(data[2]) << 8) + orb(data[3])
            cls = IP
        else:
            iplen = (orb(data[4]) << 8) + orb(data[5]) + sizeof(IPv6())
            cls = IPv6
        if iplen > dlen:
            return partial(IPTFSFrag, fraglen=dlen)
        return cls
    return conf.raw_layer


class IPTFSWithFrags(Packet):

    __slots__ = ["offset", "prevpkts"]

    name = "IPTFS"
    fields_desc = [
        FlagsField("flags", 0, 8, ["r0", "r1", "r2", "r3", "r4", "ECN", "CC", "V"]),
        XByteField("resv", 0),
        ShortField("block_offset", 0),
        PacketListField("packets", default=[], next_cls_cb=iptfs_decap_pkt_with_frags),
        # PacketListField("packets", default=[], next_cls_cb=iptfs_decap_pkt_cls),
    ]

    def __init__(
        self, _pkt=b"", post_transform=None, _internal=0, _underlayer=None, **fields
    ):
        self.prevpkts = []
        if "prevpkts" in fields:
            self.prevpkts = fields["prevpkts"]
            del fields["prevpkts"]
        # self.offset = (orb(_pkt[2]) << 8) + orb(_pkt[3])
        self.offset = 0
        Packet.__init__(self, _pkt, post_transform, _internal, _underlayer, **fields)

    def is_all_pad(self):
        return len(self.packets) == 1 and IPTFSPad in self.packets[0]

    def is_padded(self):
        return len(self.packets) and IPTFSPad in self.packets[-1]


def iptfs_decap_pkt_nofrag(ppkt, pkts, curpkt, data):
    # logger.critical("iptfs_decap_pkt: pptype %s lens: %d %d",
    # str(type(data)), len(curpkt) if curpkt is not None else 0, len(data))
    del ppkt
    del pkts
    del curpkt
    assert data
    t = orb(data[0]) & 0xF0
    if t == 0:
        return IPTFSPad
    if t == 0x40:
        return IP
    if t == 0x60:
        return IPv6
    return conf.raw_layer


class IPTFS(Packet):
    name = "IPTFS"
    fields_desc = [
        FlagsField("flags", 0, 8, ["r0", "r1", "r2", "r3", "r4", "ECN", "CC", "V"]),
        XByteField("resv", 0),
        ShortField("block_offset", 0),
        PacketListField("packets", default=[], next_cls_cb=iptfs_decap_pkt_nofrag),
    ]


class IPTFSHeader(Packet):
    name = "IPTFSHeader"
    fields_desc = [
        FlagsField("flags", 0, 8, ["r0", "r1", "r2", "r3", "r4", "ECN", "CC", "V"]),
        XByteField("resv", 0),
        ShortField("block_offset", 0),
    ]


def get_overhead(sa, is_cc=False):
    assert not is_cc
    return sa.get_ipsec_overhead() + len(IPTFSHeader())


def get_payload_size(mtu, sa, is_cc=False):
    o = get_overhead(sa, is_cc)
    r = mtu - o
    return r


def get_payload_rate(bitrate, mtu, sa, is_cc=False):
    r = (bitrate * get_payload_size(mtu, sa, is_cc)) / (mtu * 8)
    return r


def get_max_queue_size(maxdelay, bitrate, mtu, sa, is_cc=False):

    prate = get_payload_rate(bitrate, mtu, sa, is_cc)
    r = (prate * maxdelay) / 1000000
    return r


def get_max_queue_len(maxdelay, bitrate, mtu, sa, is_cc=False):
    max_size = get_max_queue_size(maxdelay, bitrate, mtu, sa, is_cc)

    return max_size / (mtu - get_overhead(sa, is_cc))


def strip_all_pads(pkts):
    """
    Given a list of IPTFS packets, strip off All pads from each end
    """
    # Remove heading pads
    i = 0
    for i, rx in enumerate(pkts):
        if len(rx.packets) != 1 or IPTFSPad not in rx.packets[0]:
            break
    pkts = pkts[i:]
    for i, rx in enumerate(reversed(pkts)):
        if len(rx.packets) != 1 or IPTFSPad not in rx.packets[0]:
            break
    dlen = len(pkts)
    return pkts[: dlen - i]


# XXX we should refactor this into a loop so we can defrag segments of a stream of
# packets.
def decap_frag_stream(pkts):
    """
    Given a list of IPTFS packets, join fragments and strip padding.
    Return a real packet list.
    """

    ippkts = []

    first = True
    fdata = b""
    flen = None
    for epkt in pkts:
        ipkts = epkt.packets
        if first and epkt.block_offset:
            logger.warning(
                "decap_frag_stream: first packet in stream "
                "starts with in progress fragment -- skipping"
            )
            ipkt = ipkts[0][IPTFSFrag]
            ipkts = ipkts[1:]
            if len(ipkt) == epkt.block_offset:
                # We have the entire fragment.
                first = False
            else:
                assert not ipkts
        first = False
        for ipkt in ipkts:
            if IPTFSPad in ipkt:
                # break? Shouldn't pad always be last
                continue

            if IP in ipkt or IPv6 in ipkt:
                if fdata:
                    logger.warning(
                        "decap_frag_stream: "
                        "in progress fragment terminated by real packet"
                    )
                    fdata = b""
                    flen = None
                ippkts.append(ipkt)
                continue

            # Determine what type of packet fragment this is.
            for fcls in [IPTFSFrag, IPTFSEndFrag, IPTFSIPFrag, IPTFSIPv6Frag]:
                if fcls in ipkt:
                    fdata += ipkt[fcls].frag
                    break
            else:
                logger.critical("Odd ipkt: %s", ipkt.show(dump=True))
                assert False

            if flen is None:
                cls, flen = get_frag_class_and_len(fdata)
            if flen is not None:
                if len(fdata) == flen:
                    # logger.critical("XXX Class: %s Length: %d", str(cls), flen)
                    ippkts.append(cls(raw(fdata)))
                    fdata = b""
                    flen = None
                else:
                    pass  # more data to come, continue to next fragment.
            else:
                pass  # no length yet, continue to next fragment.
    return ippkts


def raw_iptfs_stream(ippkts, payloadsize, dontfrag=False):
    """raw_iptfs_stream - encapsulate ippkts in a stream of iptfs packes"""
    tunpkts = [IPTFSHeader() / Raw()]
    emptylen = len(tunpkts[-1])

    payloadsize += emptylen
    for pkt in ippkts:
        again = True
        payload = Raw(pkt).load
        if dontfrag and (emptylen + len(payload) > payloadsize):
            raise ValueError(
                f"dont frag with input packet size {len(payload)}"
                f" larger than payload size {payloadsize-emptylen}"
            )
        while again:
            clen = len(tunpkts[-1])
            if clen + len(payload) > payloadsize and dontfrag:
                # Try not padding just pack the packet
                # if False:
                #     # Pad out get a new packet.
                #     tunpkts[-1][Raw].load += b"\x00" * (payloadsize - clen)

                tunpkts.append(IPTFSHeader() / Raw())
                continue

            if clen + len(payload) < payloadsize:
                tunpkts[-1][Raw].load += payload
                again = False
            elif clen + len(payload) == payloadsize:
                tunpkts[-1][Raw].load += payload
                tunpkts.append(IPTFSHeader() / Raw())
                again = False
            else:
                tunpkts[-1][Raw].load += payload[: payloadsize - clen]
                payload = payload[payloadsize - clen :]
                tunpkts.append(IPTFSHeader(block_offset=len(payload)) / Raw())
                if not payload:
                    again = False

    clen = len(tunpkts[-1])
    if clen != payloadsize:
        tunpkts[-1][Raw].load += b"\x00" * (payloadsize - clen)
    if clen == len(IPTFSHeader() / Raw()):
        tunpkts = tunpkts[:-1]
    # print("XXXLEN: raw_iptfs_stream length of payload: {}".format(
    #     len(tunpkts[-1])))

    return tunpkts


def gen_encrypt_pktstream_pkts(  # pylint: disable=W0612  # pylint: disable=R0913
    sa, mtu, pkts, dontfrag=False
):

    # for pkt in pkts:
    #     self.logger.debug(" XXX: len: {} pkt: {}".format(
    #         len(pkt), pkt.show(dump=True)))

    ipsec_payload_size = mtu - sa.get_ipsec_overhead()
    ipsec_payload_size = (ipsec_payload_size // 4) * 4
    tunpkts = [
        sa.encrypt_esp_raw(rawpkt)
        for rawpkt in raw_iptfs_stream(pkts, ipsec_payload_size, dontfrag)
    ]

    return tunpkts


def gen_encrypt_pktstream(  # pylint: disable=W0612  # pylint: disable=R0913,R0914
    sa,
    sw_intf,
    src,
    dst,
    mtu,
    count=1,
    payload_size=54,
    payload_spread=0,
    dontfrag=False,
):

    # XXX IPv6
    if not payload_spread:
        pstream = [
            IP(src=src, dst=dst) / ICMP(seq=i) / Raw("d" * payload_size)
            for i in range(count)
        ]
    else:
        pstream = []
        start = payload_size
        end = payload_spread
        psize = start
        for i in range(count):
            pstream.append(IP(src=src, dst=dst) / ICMP(seq=i) / Raw("X" * (psize)))
            psize += 1
            if psize == end:
                psize = start

    # for pkt in pstream:
    #     self.logger.debug(" XXX: len: {} pkt: {}".format(
    #         len(pkt), pkt.show(dump=True)))

    ipsec_payload_size = mtu - sa.get_ipsec_overhead()
    ipsec_payload_size = (ipsec_payload_size // 4) * 4
    pstream = raw_iptfs_stream(pstream, ipsec_payload_size, dontfrag)
    # self.logger.debug(" XXXPKT: len: {} pkt: {}".format(
    #     len(pstream[0]),
    #     IPTFS(pstream[0]).show(dump=True)))
    tunpkts = [
        Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac)
        / sa.encrypt_esp_raw(rawpkt)
        for rawpkt in pstream
    ]

    return tunpkts


def gen_encrypt_pkts(sa, sw_intf, src, dst, count=1, payload_size=54):
    # XXX IPv6
    return [
        Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac)
        / sa.encrypt(IP(src=src, dst=dst) / ICMP(seq=i) / Raw("d" * payload_size))
        for i in range(count)
    ]


class SecurityAssociation(ipsec.SecurityAssociation):
    """
    This class is responsible of "encryption" and "decryption" of IPsec IPTFS packets.
    """

    def __init__(self, *args, **kwargs):
        self.mtu = 1500
        if "mtu" in kwargs:
            self.mtu = kwargs["mtu"]
            del kwargs["mtu"]
        super().__init__(*args, **kwargs)
        self.ipsec_overhead = self._get_ipsec_overhead()

    def get_ipsec_overhead(self):
        return self.ipsec_overhead

    def _get_ipsec_overhead(self):
        # _ESPPlain includes the footer fields
        ol = len(self.tunnel_header / _ESPPlain())
        if self.nat_t_header is not None:
            ol += len(self.nat_t_header())

        # compensate for IPTFS header overhead
        ol += 4

        # print("XXXLEN: get_ipsec_overhead thlen: {} esp: {}".format(
        #     len(self.tunnel_header), len(_ESPPlain())))
        # print("XXXLEN: get_ipsec_overhead ol: {} icv: {} iv: {}".format(
        #     ol, self.crypt_algo.icv_size, self.crypt_algo.iv_size))
        if self.crypt_algo.icv_size:
            return ol + (self.crypt_algo.icv_size + self.crypt_algo.iv_size)
        return ol + (self.auth_algo.icv_size + self.crypt_algo.iv_size)

    def build_seq_num(self, num):
        "return sequence number component parts"
        lower = num & 0xFFFFFFFF
        upper = num >> 32

        if self.esn_en:
            return lower, struct.pack("!I", upper)
        return lower, None

    def encrypt_esp_raw(self, payload, seq_num=None, iv=None, esn_en=None, esn=None):
        if iv is None:
            iv = self.crypt_algo.generate_iv()
        else:
            if len(iv) != self.crypt_algo.iv_size:
                raise TypeError("iv length must be %s" % self.crypt_algo.iv_size)

        low_seq_num, high_seq_num = self.build_seq_num(seq_num or self.seq_num)
        esp = _ESPPlain(spi=self.spi, seq=low_seq_num, iv=iv)

        assert self.tunnel_header
        tunnel = self.tunnel_header.copy()
        if tunnel.version == 4:
            del tunnel.proto
            del tunnel.len
            del tunnel.chksum
        else:
            del tunnel.nh
            del tunnel.plen
        pkt = tunnel.__class__(raw(tunnel / payload))

        ip_header, _, payload = split_for_transport(pkt, socket.IPPROTO_ESP)

        # logger.critical(
        #     "XXX: enc: pktlen: {} class: {} payload len: {} seq: {}".format(
        #         len(pkt), tunnel.__class__, len(payload), low_seq_num))

        # print("XXX: enc: pktlen: {} class: {} payload len: {} show: {}".format(
        #     len(pkt), tunnel.__class__, len(payload), pkt.show(dump=True)))

        esp.data = payload
        esp.nh = IPPROTO_IPTFS
        esp = self.crypt_algo.pad(esp)
        esp = self.crypt_algo.encrypt(
            self, esp, self.crypt_key, esn_en=esn_en or self.esn_en, esn=esn or self.esn
        )
        self.auth_algo.sign(esp, self.auth_key, high_seq_num)

        if ip_header.version == 4:
            ip_header.len = len(ip_header) + len(esp)
            del ip_header.chksum
            ip_header = ip_header.__class__(raw(ip_header))
        else:
            ip_header.plen = len(ip_header.payload) + len(esp)

        # sequence number must always change, unless specified by the user
        if seq_num is None:
            self.seq_num += 1

        newpkt = ip_header / esp
        return newpkt

    def _encrypt_esp(self, pkt, seq_num=None, iv=None, esn_en=None, esn=None):
        # This path (sa.encrypt) only supports a single IP[v6] internal packet.
        overhead = 4 + self.ipsec_overhead
        payload = raw(pkt)
        assert len(payload) <= (self.mtu - overhead)
        pad = b"\x00" * (self.mtu - len(payload) - overhead)
        payload = b"\x00\x00\x00\x00" + raw(payload) + pad
        return self.encrypt_esp_raw(payload, seq_num, iv, esn_en, esn)

    def _decrypt_esp(
        self, pkt, verify=True, esn_en=None, esn=None, prevpkts=None
    ):  # pylint: disable=W0221

        _, high_seq_num = self.build_seq_num(self.seq_num)
        encrypted = pkt[ESP]

        if verify:
            self.check_spi(pkt)
            self.auth_algo.verify(encrypted, self.auth_key, high_seq_num)

        esp = self.crypt_algo.decrypt(
            self,
            encrypted,
            self.crypt_key,
            self.crypt_algo.icv_size or self.auth_algo.icv_size,
            esn_en=esn_en or self.esn_en,
            esn=esn or self.esn,
        )

        assert self.tunnel_header
        # drop the tunnel header and return the payload untouched

        pkt.remove_payload()

        if esp.nh == IPPROTO_IPTFS:
            if prevpkts is not None:
                cls = partial(IPTFSWithFrags, prevpkts=prevpkts)
            else:
                cls = IPTFSWithFrags
        else:
            if pkt.version == 4:
                pkt.proto = esp.nh
            else:
                pkt.nh = esp.nh
            cls = pkt.guess_payload_class(esp.data)

        # This swap is required b/c PacketFieldList only considers layers of this type
        # in a packet to be actually part of the next packet. We probably want to figure
        # out how to get IPTFSFrag to have the extra remaining data added as Padding
        # instead of Raw.

        # Aaand this doesn't work b/c test IP packets lose their payloads.

        # old = conf.padding_layer
        # conf.padding_layer = Raw
        mypkt = cls(esp.data, prevpkts)
        # conf.padding_layer = old
        return mypkt

    def decrypt_iptfs_pkt(self, pkt, prevpkts=None, verify=True, esn_en=None, esn=None):
        return self._decrypt_esp(pkt, verify, esn_en, esn, prevpkts)


bind_layers(ESP, IPTFS, nh=IPPROTO_IPTFS)

__author__ = "Christian Hopps"
__date__ = "July 14 2019"
__version__ = "1.0"
__docformat__ = "restructuredtext en"
