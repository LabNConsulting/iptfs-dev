# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# September 22 2022, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2022, LabN Consulting, L.L.C.
#

ESP = "tshark -td -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e ip.proto  -e icmp.seq -e esp.sequence -r capture-net1.pcap ip.src==11.0.0.2 and esp"

ICMP = "tshark -td -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e ip.proto  -e icmp.seq -r capture-net0.pcap icmp and ip.src==11.0.0.1"
