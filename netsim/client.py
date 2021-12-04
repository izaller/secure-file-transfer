###-----------------------------------------------###
# implementation of client operations for secure
# file transfer
###-----------------------------------------------###

import sys, os
from netinterface import network_interface
from client_interface import login, welcome, build_msg, process_input
from user import User
from aes_ops import check_sqn, decrypt

SUCCESS = '1'
FAILURE = '0'

NET_PATH = './network'
OWN_ADDR = input('Enter user address: ')

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

if not os.access(NET_PATH, os.F_OK):
    print('Error: Cannot access path ' + NET_PATH)
    sys.exit(1)

if len(OWN_ADDR) > 1: OWN_ADDR = OWN_ADDR[0]

if OWN_ADDR not in network_interface.addr_space:
    print('Error: Invalid address ' + OWN_ADDR)
    sys.exit(1)

netif = network_interface(NET_PATH, OWN_ADDR)
user = User(OWN_ADDR)
dst = 'S'   ## set destination to server

## login protocol
user.session = login(netif, OWN_ADDR)
if user.session is not None:
    welcome(user.addr)
    while True:
        # user.session.print()
        inp = input('Type a command: ')

        cmd, arg = process_input(inp)
        if cmd is None:
            continue

        # build message based on input
        msg = build_msg(user.addr, user.session, cmd, arg)

        # send message
        netif.send_msg(dst, msg)
        user.session.sqn_snd += 1

        # wait for response
        status, rsp = netif.receive_msg(blocking=True)  # when returns, status is True and msg contains a message

        # check sqn_rsp > user.session.sqn_rcv (in header, don't need to decrypt)
        sqn_rsp = int.from_bytes(rsp[17:21], byteorder='big')
        if check_sqn(user.session.sqn_rcv, sqn_rsp):
            # decrypt rsp
            addr, rsp_code, arg = decrypt(rsp, user.session.key)   # we don't care about addr (S) or arg (should be empty string)

            # set user.session.rsp = sqn_rsp
            user.session.sqn_rcv = sqn_rsp

            # check success/failure code
            if rsp_code == SUCCESS:
                print(cmd)
                if cmd == 'LOGOUT':
                    print('Logout success. Goodbye.')
                    quit()
                print('Command successfully executed')
            else:
                print('Unable to complete command')
        # print success/failure message
        else:
            print('message sequence number not accepted')
