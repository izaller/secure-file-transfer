###-----------------------------------------------###
# implementation of client operations for secure
# file transfer
###-----------------------------------------------###

import sys, os
from netinterface import network_interface

NET_PATH = './network'
OWN_ADDR = 'U'

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

if not os.access(NET_PATH, os.F_OK):
    print('Error: Cannot access path ' + NET_PATH)
    sys.exit(1)

if len(OWN_ADDR) > 1: OWN_ADDR = OWN_ADDR[0]

if OWN_ADDR not in network_interface.addr_space:
    print('Error: Invalid address ' + OWN_ADDR)
    sys.exit(1)

print(NET_PATH, OWN_ADDR)

netif = network_interface(NET_PATH, OWN_ADDR)


dst = 'S'   ## set destination to server
print('Main client loop started...')
while True:
    msg = input('Type a message: ')
    msg = OWN_ADDR + msg
    netif.send_msg(dst, msg.encode('utf-8'))

    status, rsp = netif.receive_msg(blocking=True)  # when returns, status is True and msg contains a message
    print(rsp.decode('utf-8'))

    if input('Continue? (y/n): ') == 'n': break
