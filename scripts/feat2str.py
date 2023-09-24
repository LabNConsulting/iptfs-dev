# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# September 14 2023, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2023, LabN Consulting, L.L.C.
#
"Convert an integer to linux kernel features flags"
import argparse
import logging

flag_strings = [
    "SG_BIT",
    "IP_CSUM_BIT",
    "__UNUSED_1",
    "HW_CSUM_BIT",
    "IPV6_CSUM_BIT",
    "HIGHDMA_BIT",
    "FRAGLIST_BIT",
    "HW_VLAN_CTAG_TX_BIT",
    "HW_VLAN_CTAG_RX_BIT",
    "HW_VLAN_CTAG_FILTER_BIT",
    "VLAN_CHALLENGED_BIT",
    "GSO_BIT",
    "LLTX_BIT",
    "NETNS_LOCAL_BIT",
    "GRO_BIT",
    "LRO_BIT",
    "TSO_BIT",
    "GSO_ROBUST_BIT",
    "TSO_ECN_BIT",
    "TSO_MANGLEID_BIT",
    "TSO6_BIT",
    "FSO_BIT",
    "GSO_GRE_BIT",
    "GSO_GRE_CSUM_BIT",
    "GSO_IPXIP4_BIT",
    "GSO_IPXIP6_BIT",
    "GSO_UDP_TUNNEL_BIT",
    "GSO_UDP_TUNNEL_CSUM_BIT",
    "GSO_PARTIAL_BIT",
    "GSO_TUNNEL_REMCSUM_BIT",
    "GSO_SCTP_BIT",
    "GSO_ESP_BIT",
    "GSO_UDP_BIT",
    "GSO_UDP_L4_BIT",
    "GSO_FRAGLIST_BIT",
    "FCOE_CRC_BIT",
    "SCTP_CRC_BIT",
    "FCOE_MTU_BIT",
    "NTUPLE_BIT",
    "RXHASH_BIT",
    "RXCSUM_BIT",
    "NOCACHE_COPY_BIT",
    "LOOPBACK_BIT",
    "RXFCS_BIT",
    "RXALL_BIT",
    "HW_VLAN_STAG_TX_BIT",
    "HW_VLAN_STAG_RX_BIT",
    "HW_VLAN_STAG_FILTER_BIT",
    "HW_L2FW_DOFFLOAD_BIT",
    "HW_TC_BIT",
    "HW_ESP_BIT",
    "HW_ESP_TX_CSUM_BIT",
    "RX_UDP_TUNNEL_PORT_BIT",
    "HW_TLS_TX_BIT",
    "HW_TLS_RX_BIT",
    "GRO_HW_BIT",
    "HW_TLS_RECORD_BIT",
    "GRO_FRAGLIST_BIT",
    "HW_MACSEC_BIT",
    "GRO_UDP_FWD_BIT",
    "HW_HSR_TAG_INS_BIT",
    "HW_HSR_TAG_RM_BIT",
    "HW_HSR_FWD_BIT",
    "HW_HSR_DUP_BIT",
]



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true", help='Be verbose')
    parser.add_argument("flags",  help='integer to convert to flag strings')
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s: %(message)s")

    flags = int(args.flags, 16)
    set_flags = []
    for i, flag in enumerate(flag_strings):
        if (1 << i) & flags:
            set_flags.append(flag)

    print(set_flags)


if __name__ == "__main__":
    main()
