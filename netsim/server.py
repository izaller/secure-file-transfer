###-----------------------------------------------###
# server operations for secure file transfer
###-----------------------------------------------###

import os
import sys

from netinterface import network_interface
from server_interface import Serverif

NET_PATH = './network'
OWN_ADDR = 'S'
LOGGED_IN_USER = None

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

if not os.access(NET_PATH, os.F_OK):
    print('Error: Cannot access path ' + NET_PATH)
    sys.exit(1)

if len(OWN_ADDR) > 1: OWN_ADDR = OWN_ADDR[0]

if OWN_ADDR not in network_interface.addr_space:
    print('Error: Invalid address ' + OWN_ADDR)
    sys.exit(1)

netif = network_interface(NET_PATH, OWN_ADDR)
serverif = Serverif(OWN_ADDR, NET_PATH)
# status, msg = netif.receive_msg(blocking=True)  # when returns, status is True and msg contains a message

print('Main loop started, quit with pressing CTRL-C...')
while True:
    # wait for message
    status, msg = netif.receive_msg(blocking=True)  # when returns, status is True and msg contains a message
    serverif.process_msg(netif, status, msg)


