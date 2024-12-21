#!/usr/bin/env python3
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# This code was originally written by chatgpt

# import logging
import socket
import sys

# root = logging.getLogger()
# root.setLevel(logging.DEBUG)
# handler = logging.StreamHandler(sys.stdout)
# handler.setLevel(logging.DEBUG)
# formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
# handler.setFormatter(formatter)
# root.addHandler(handler)

try:
    # logging.info("countudp starting up")

    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind the socket to the port
    server_address = ("", 5202)
    # logging.info("binding on %s port %s", *server_address)
    print("binding on %s port %s" % server_address)
    sys.stdout.flush()
    sock.bind(server_address)

    # Initialize the counter
    counter = 0

    while True:
        # Receive data
        data, address = sock.recvfrom(4096)

        # Increment the counter
        counter += 1
        if (counter % 100) == 0:
            print("received dgrams: ", counter)
            sys.stdout.flush()

except Exception as error:
    # logging.error("Got exception: %s", error)
    print("Got exception: ", error)
    sys.stdout.flush()
