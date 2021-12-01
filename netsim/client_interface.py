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

RSA_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2KLWOGq+DKVqRaDqFzyk\n4oF37h/BnJsNJrK03id3x7KdFqv6Fzx3pptX7LJW3B5ECmQqG5tUhR7x+SLsIbNv\nWokruHVe8t8S0Y84Lg4eAbqu04+51wtgbX9wHQXHRaurSZn6LbFoZynPjvoaAAFW\nOPGDsnGYMFmZPRkUuk06q0/3hak8Rg1HGY1PDrVF54VSZ1w/Obj0n7WALFCHjtir\nk8aKQUfrS1+WVpqCz2HDtKUfJl4r4Tqs/abZwrsN5S4vpqy9MplBnnin2TUviRpi\n1Qpjsl2kT8MD0hUd8aX+qEy8aCn8NahztTyICQsfYDsBpZAVK5W12bJkqjAHUCA+\nGNTnUWBcujg1cApzOT/0p0AW/W0DNFoho1jyLhRj5FXTo+pTshweUceldjkZePwn\nT3b7LecvX42V35OELC0wsY/2t46PfKJKRHHxiAoBVrmxdhYJCEsSWAZ34Pzw+nQ8\nA5pXVHJLs7LWmFjWatyNhDRNhzEcRIKLv5OXEcDaqRaR3PXAz0JhsrQfenicJksZ\nMpb2ygdZFE2HoYgSkZvcRl2FOvoD7zFEFw5kTB34lcuVt6CzJ1O3M24X9qzLUP+Y\nTmANypBbMs8w+GlaUrD9T76C8oyyOxBH7QCisf2StUMwg1+V4W8LjGD4HFXP77bv\nHlgEe5RKf3cub7hWlQRGgWcCAwEAAQ==\n-----END PUBLIC KEY-----'
RSA_PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----'

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

# TODO: implement
def public_encrypt(pswd):
    return pswd

# TODO: implement
def sign(msg, sqn):
    return ''

def login(netif, addr):
    # input password in terminal
    password_accepted = False

    while not password_accepted:
        pswd = input('Enter password: ')
        # encrypt password with public key
        # add check for password length? - can't be longer than RSA block size
        pubkey = RSA.import_key(RSA_PUBLIC_KEY) # change how this is stored, just using as a placeholder
        rsa_cipher = PKCS1_OAEP.new(pubkey)
        cipher_pswd = rsa_cipher.encrypt(pswd.encode('utf-8'))
        str_pswd = str(int.from_bytes(cipher_pswd, 'big'))
        padded_pswd = str_pswd + 'x' * (1536 - len(str_pswd))

        # build login request
        ## [address | login request | password | g^x mod p | sig(...)]
        ## one byte | one byte | 512 bytes | 256 bytes | ??

        # compute g^x mod p
        dh = pyDH.DiffieHellman()
        gxmodp = dh.gen_public_key()
        msg = addr + commands['LOGIN'] + public_encrypt(padded_pswd) + str(gxmodp)
        # TODO: sign message with MSN
        sqn = ''
        sig = sign(msg, sqn)
        msg = msg + sig

        # send login request
        netif.send_msg(server, msg.encode('utf-8'))

        # wait for server response
        status, rsp = netif.receive_msg(blocking=True)

        # parse response message for accept/reject
        login_response = rsp.decode('utf-8')[0]     # get first byte
        if login_response == SERVER_UNAVAILABLE:
            print('The server is currently unavailable. Please try again later.')
            break

        # check if password was accepted
        password_accepted = (login_response == LOGIN_SUCCESS)

        # generate session key from DH key and store
        if password_accepted:

            gymodp = int(rsp.decode('utf-8')[1:618])

            # authenticate signature
            # using RSA-PSS (dif from design doc, but works with other RSA throughout project)
            msg_signed = addr + str(gxmodp) + server + str(gymodp)
            h = SHA512.new()
            h.update(msg_signed.encode('utf-8'))
            verifier = PKCS1_PSS.new(pubkey)

            rsp_signature = rsp.decode('utf-8')[618:]
            rsp_signature = rsp_signature[:rsp_signature.index('x')]
            signature = int(rsp_signature).to_bytes(length=512, byteorder='big')

            if verifier.verify(h, signature):
                print('Signature verified')
            else:
                print('Signature verification failed')
                break

            # TODO: send final signed message w all DH parameters
            sig = ''

            # TODO: msg_final = [U | salt | sigU(addr | g^x mod p | S | g^y mod p)]
            salt = get_random_bytes(16)
            str_salt = str(int.from_bytes(salt, 'big'))
            padded_salt = str_salt + 'x' * (48 - len(salt))
            #msg_final = addr + str(int.from_bytes(salt, 'big')) + sig
            msg_final = addr + padded_salt + sig
            netif.send_msg(server, msg_final.encode('utf-8'))

            shared_key = dh.gen_shared_key(gymodp)
            print(shared_key.encode('utf-8'))
            AES_key = HKDF(shared_key.encode('utf-8'), 32, salt, SHA512, 1)
            print('AES_key', AES_key)

            # create session and return user
            session = Session('S', AES_key)
            return session

        print('Password incorrect. Please try again')
