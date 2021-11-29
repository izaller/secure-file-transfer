###-----------------------------------------------###
# implementation of client operations for secure
# file transfer
###-----------------------------------------------###

import pyDH
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from session import Session
from user import User

server = 'S'
LOGIN_SUCCESS = '1'
SERVER_UNAVAILABLE = 'X'
commands = {'LOGIN': '0',
            'MKD': '1',
            'RMD': '2',
            'GWD': '3',
            'CWD': '4',
            'LST': '5',
            'UPL': '6',
            'DNL': '7',
            'RMF': '8',
            'LOGOUT': '9'}

def welcome(addr):
    print('Login success. Welcome,', addr)
    print('You may now use the following commands:')
    print(' MKD [dirname]       --make directory with name dirname on the server')
    print(' RMD [dirname]       --remove directory with name dirname from the server')
    print(' GWD                 --print the name of the current working directory')
    print(' CWD [dirname]       --change the current directory to the directory named dirname')
    print(' LST [dirname]       --list the contents of the directory on the server named dirname')
    print(' UPL [path to file]  --upload the file located at the input file path to the\n'
          '                       current working directory on the server')
    print(' DNL [filename]      --download the file named filename from the current directory')
    print(' RMF [filename]      --delete the file named filename from the current directory')
    print(' LOGOUT              --log off from the server')

# build message to server from user input
def build_msg(addr, inp):
    # TODO: add msg length, signature/MAC w/ msg sqn #, encryption, padding on fields
    split = inp.split()
    if len(split) > 2:
        print('Too many arguments: ' + inp + ' is not a valid command input.')
        return None

    # check input validity
    cmd = split[0].upper()
    if cmd not in commands.keys():
        print(cmd + ' is not a valid command.')
        return None

    arg = ''
    ## check for necessary arguments
    if cmd != 'GWD' and cmd != 'LOGOUT':
        if len(split) == 1:
            argname = 'dirname'
            if cmd == 'UPL':
                argname = 'path to file'
            elif cmd == 'DNL' or cmd == 'RMF':
                argname = 'filename'
            print(cmd + ' requires argument: ' + argname)
            return None
        arg = split[1]

    cmd_code = commands[cmd]
    return addr + cmd_code + arg

def login(netif, addr):
    # input password in terminal
    password_accepted = False
    user = User(addr)
    while not password_accepted:
        pswd = input('Enter password: ')
        # TODO: encrypt password with public key
        # build login request
        ## [address | login request | password | g^x mod p | sig(...)]
        ## one byte | one byte | 12 bytes | 256 bytes | ??

        # compute g^x mod p
        dh = pyDH.DiffieHellman()
        gxmodp = dh.gen_public_key()
        msg = addr + commands['LOGIN'] + pswd + str(gxmodp)

        # TODO: sign message with MSN
        sig = ''
        msg = msg + sig

        # send login request
        netif.send_msg(server, msg.encode('utf-8'))

        # TODO: set timer
        # wait for server response
        status, rsp = netif.receive_msg(blocking=True)
        # TODO: parse response message for accept/reject
        login_response = rsp.decode('utf-8')[0]     # get first byte
        if login_response == SERVER_UNAVAILABLE:
            print('The server is currently unavailable. Please try again later.')
            break

        # parse received message
        password_accepted = (login_response == LOGIN_SUCCESS)

        # generate session key from DH key and store
        if password_accepted:
            # TODO: authenticate signature

            gymodp = int(rsp.decode('utf-8')[1:])
            salt = get_random_bytes(16)

            # TODO: sign message w all DH parameters and salt
            sig = ''

            # msg_final = [U | salt | sigU(addr | g^x mod p | S | g^y mod p)]
            msg_final = addr.encode('utf-8') + salt + sig.encode('utf-8')
            netif.send_msg(server, msg_final)

            shared_key = dh.gen_shared_key(gymodp)
            AES_key = HKDF(shared_key.encode('utf-8'), 32, salt, SHA512, 1)
            print('AES_key', AES_key)

            # create session and return user
            user.session = Session('S', AES_key)
            return user
        print('Password incorrect. Please try again')
