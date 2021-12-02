###-----------------------------------------------###
# implementation of client operations for secure
# file transfer
###-----------------------------------------------###

import pyDH
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from session import Session
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from aes_ops import encrypt

# server's public key
RSA_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2KLWOGq+DKVqRaDqFzyk\n4oF37h/BnJsNJrK03id3x7KdFqv6Fzx3pptX7LJW3B5ECmQqG5tUhR7x+SLsIbNv\nWokruHVe8t8S0Y84Lg4eAbqu04+51wtgbX9wHQXHRaurSZn6LbFoZynPjvoaAAFW\nOPGDsnGYMFmZPRkUuk06q0/3hak8Rg1HGY1PDrVF54VSZ1w/Obj0n7WALFCHjtir\nk8aKQUfrS1+WVpqCz2HDtKUfJl4r4Tqs/abZwrsN5S4vpqy9MplBnnin2TUviRpi\n1Qpjsl2kT8MD0hUd8aX+qEy8aCn8NahztTyICQsfYDsBpZAVK5W12bJkqjAHUCA+\nGNTnUWBcujg1cApzOT/0p0AW/W0DNFoho1jyLhRj5FXTo+pTshweUceldjkZePwn\nT3b7LecvX42V35OELC0wsY/2t46PfKJKRHHxiAoBVrmxdhYJCEsSWAZ34Pzw+nQ8\nA5pXVHJLs7LWmFjWatyNhDRNhzEcRIKLv5OXEcDaqRaR3PXAz0JhsrQfenicJksZ\nMpb2ygdZFE2HoYgSkZvcRl2FOvoD7zFEFw5kTB34lcuVt6CzJ1O3M24X9qzLUP+Y\nTmANypBbMs8w+GlaUrD9T76C8oyyOxBH7QCisf2StUMwg1+V4W8LjGD4HFXP77bv\nHlgEe5RKf3cub7hWlQRGgWcCAwEAAQ==\n-----END PUBLIC KEY-----'

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
def build_msg(addr, session, inp):

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

    header = addr.encode('utf-8') + session.sqn_snd.to_bytes(length=4, byteorder='big')   # header: addr + msn (5 bytes)
    plaintext = cmd_code.encode('utf-8') + arg.encode('utf-8')  # encrypted content: cmd + arg

    return encrypt(session.key, header, plaintext)

def public_encrypt(pubkey, pswd):
    rsa_cipher = PKCS1_OAEP.new(pubkey)
    return rsa_cipher.encrypt(pswd.encode('utf-8'))

# using RSA-PSS (dif from design doc, but works with other RSA throughout project)
def sig_verified(pubkey, msg_signed, rsp_signature):
    h = SHA512.new()
    h.update(msg_signed.encode('utf-8'))
    verifier = PKCS1_PSS.new(pubkey)
    return verifier.verify(h, rsp_signature)

def login(netif, addr):
    # input password in terminal
    password_accepted = False

    while not password_accepted:
        pswd = input('Enter password: ')
        # encrypt password with public key
        # add check for password length? - can't be longer than RSA block size
        pubkey = RSA.import_key(RSA_PUBLIC_KEY)  # change how this is stored, just using as a placeholder

        #  login request:
        ## [address | login request | password | g^x mod p | sig(...)]
        ## one byte | one byte | 512 bytes | 256 bytes | ??

        # compute g^x mod p
        dh = pyDH.DiffieHellman()
        gxmodp = dh.gen_public_key()

        # generate salt for HKDF
        salt = get_random_bytes(16)

        # build login message
        encoded_pswd = public_encrypt(pubkey, pswd)
        msg = (addr + commands['LOGIN']).encode('utf-8') + encoded_pswd + gxmodp.to_bytes(length=256, byteorder='big') + salt

        # send login request
        netif.send_msg(server, msg)

        # wait for server response
        status, rsp = netif.receive_msg(blocking=True)

        # parse response message for accept/reject
        login_response = chr(rsp[0])     # get first byte
        if login_response == SERVER_UNAVAILABLE:
            print('The server is currently unavailable. Please try again later.')
            break

        # check if password was accepted
        password_accepted = (login_response == LOGIN_SUCCESS)

        # generate session key from DH key and store
        if password_accepted:

            gymodp = int.from_bytes(rsp[1:257], byteorder='big')

            # authenticate signature
            msg_signed = addr + str(gxmodp) + server + str(gymodp)
            rsp_signature = rsp[257:]
            if sig_verified(pubkey, msg_signed, rsp_signature):
                print('Signature verified')
            else:
                print('Signature verification failed')
                break

            # generate shared key from Diffie-Hellman parameters
            shared_key = dh.gen_shared_key(gymodp)

            # generate AES key with HKDF using shared key and salt
            AES_key = HKDF(shared_key.encode('utf-8'), 32, salt, SHA512, 1)

            # create session and return user
            session = Session('S', AES_key)
            return session

        print('Password incorrect. Please try again')
