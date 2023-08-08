#!/usr/bin/env python3
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# August 16 2023, Christian Hopps <chopps@labn.net>
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
"IKE strongswan config support"

import argparse
import logging
from math import log2


def get_local_ip(ipid):
    if ipid == 2:
        return "10.0.1.2"
    if ipid == 3:
        return "10.0.1.3"
    if ipid == 4:
        return "10.0.2.4"
    assert False
    return ""


def get_ike_config(
    ipid,
    other_ipid,
    nconn=1,
    trex=False,
    ike_reauth="6000m",
    ike_rekey="600m",
    esp_rekey="30m",
    ike_proposals="aes256gcm16-prfsha1-modp2048",
    esp_proposals="aes256gcm16-prfsha1",
):

    if not trex:
        local_trex_preip = None
        remote_trex_preip = None

    if ipid == 2:
        assert other_ipid != 2
        local_preip = "10.0.0"
        local_preip2 = "11.11.11"
        remote_preip2 = "12.12.12"
        if other_ipid == 3:
            remote_preip = "10.0.2"
        else:
            assert other_ipid == 4
            remote_preip = "10.0.3"

        if trex:
            local_trex_preip = "16.0.0"
            remote_trex_preip = "48.0.0"
    else:
        remote_preip = "10.0.0"
        remote_preip2 = "11.11.11"
        local_preip2 = "12.12.12"
        if ipid == 3:
            local_preip = "10.0.2"
        else:
            assert ipid == 4
            local_preip = "10.0.3"
        if trex:
            local_trex_preip = "48.0.0"
            remote_trex_preip = "16.0.0"

    nconn_log2 = int(log2(nconn))
    NPL = 24 + nconn_log2
    inc = 2 ** (8 - nconn_log2)
    last = 0

    ike_conf = "\nconnections {"
    for i in range(0, nconn):

        local_ts_str = (
            f"local_ts={local_preip}.{last}/{NPL},{local_preip2}.{last}/{NPL}"
        )
        if local_trex_preip:
            local_ts_str += f",{local_trex_preip}.{last}/{NPL}"

        remote_ts_str = (
            f"remote_ts={remote_preip}.{last}/{NPL},{remote_preip2}.{last}/{NPL}"
        )
        if remote_trex_preip:
            remote_ts_str += f",{remote_trex_preip}.{last}/{NPL}"

        ike_conf += f"""
    net-{i} {{
        mobike=no
        version=2
        reauth_time = {ike_reauth}
        rekey_time = {ike_rekey}
        local_addrs = {get_local_ip(ipid)}
        remote_addrs = {get_local_ip(other_ipid)}
        proposals = {ike_proposals}
        local {{
            id = user-{ipid}
            auth=psk
        }}
        remote {{
            id = user-{other_ipid}
            auth=psk
        }}
        children {{
            linux-{i + 1} {{
                {local_ts_str}
                {remote_ts_str}
                rekey_time = {esp_rekey}
                esp_proposals = {esp_proposals}
            }}
        }}
    }}"""
        last += inc

    ike_conf += f"""
}}
secrets {{
    # PSK secret
    ike-1 {{
        id-a = user-{ipid}
        id-b = user-{other_ipid}
        secret = 0sv+NkxY9LLZvwj4qCC2o/gGrWDF2d21jL
        secret = 29577a3c6ec833712dd0f614f727a72182c800af1b068b168c2806568c28065
    }}
}}
"""

    return ike_conf


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true", help="Be verbose")
    parser.add_argument(
        "-n", "--connections", type=int, default=1, help="number of connections"
    )
    parser.add_argument(
        "ipid", type=int, default=2, help="last digit (id) of left router"
    )
    parser.add_argument(
        "otheripid", type=int, default=3, help="last digit (id) of right router"
    )
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s: %(message)s")

    nconn2 = log2(args.connections)
    assert nconn2 == int(nconn2), "number of connects should be power of 2"

    print(get_ike_config(args.ipid, args.otheripid, nconn=args.connections))


if __name__ == "__main__":
    main()
