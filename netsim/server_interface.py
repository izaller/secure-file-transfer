###-----------------------------------------------###
# implementation of server operations for secure
# file transfer
###-----------------------------------------------###

import pyDH
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS

from session import Session

RSA_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2KLWOGq+DKVqRaDqFzyk\n4oF37h/BnJsNJrK03id3x7KdFqv6Fzx3pptX7LJW3B5ECmQqG5tUhR7x+SLsIbNv\nWokruHVe8t8S0Y84Lg4eAbqu04+51wtgbX9wHQXHRaurSZn6LbFoZynPjvoaAAFW\nOPGDsnGYMFmZPRkUuk06q0/3hak8Rg1HGY1PDrVF54VSZ1w/Obj0n7WALFCHjtir\nk8aKQUfrS1+WVpqCz2HDtKUfJl4r4Tqs/abZwrsN5S4vpqy9MplBnnin2TUviRpi\n1Qpjsl2kT8MD0hUd8aX+qEy8aCn8NahztTyICQsfYDsBpZAVK5W12bJkqjAHUCA+\nGNTnUWBcujg1cApzOT/0p0AW/W0DNFoho1jyLhRj5FXTo+pTshweUceldjkZePwn\nT3b7LecvX42V35OELC0wsY/2t46PfKJKRHHxiAoBVrmxdhYJCEsSWAZ34Pzw+nQ8\nA5pXVHJLs7LWmFjWatyNhDRNhzEcRIKLv5OXEcDaqRaR3PXAz0JhsrQfenicJksZ\nMpb2ygdZFE2HoYgSkZvcRl2FOvoD7zFEFw5kTB34lcuVt6CzJ1O3M24X9qzLUP+Y\nTmANypBbMs8w+GlaUrD9T76C8oyyOxBH7QCisf2StUMwg1+V4W8LjGD4HFXP77bv\nHlgEe5RKf3cub7hWlQRGgWcCAwEAAQ==\n-----END PUBLIC KEY-----'
RSA_PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----'
RSA_BLOCK_SIZE = 512 * 3 # using 4096 when generating key

CORRECT_PASSWORD = '1'
LOGIN_FAILURE = '0'
SERVER_UNAVAILABLE = 'X'

LOGIN = '0'
MKD = '1'
RMD = '2'
GWD = '3'
CWD = '4'
LST = '5'
UPL = '6'
DNL = '7'
RMF = '8'
LOGOUT = '9'
PASSWORD = 'password'

class Serverif:
    addr = ''
    path = ''
    session = None

    def __init__(self, addr, path):
        self.addr = addr
        self.path = path

    def process_msg(self, netif, status, msg):
        # msg is received as byte string

        ## route to login TODO: fix for stop server while client is still running
        if self.session is None:
            self.session = login(netif, msg)
            return

        # TODO: decode message (byte string)
        plainstr = decrypt(msg, self.session.key)

        # get sender
        addr = plainstr[0]

        # check server availability
        print('Checking server availability')
        if self.session.partner != addr:
            rsp = SERVER_UNAVAILABLE
            netif.send_msg(addr, rsp.encode('utf-8'))
            print('User ' + addr + ' tried to send message, but server is in session with user ' + self.session.partner)
            return
        print('Server available.')
        # get message command type and argument
        cmd = str(plainstr[1])

        if cmd == LOGIN:
            print('Login request received for user ' + addr)
            login(netif, msg)
            # pswd = str(plainstr[2:10])
            # gxmodp = int(plainstr[10:])     # TODO: parse message and get g^x mod p
            # sig_u = ''  # TODO: authenticate sig (possibly before this in the function)
            # self.session = login(netif, addr, pswd, gxmodp)     # arg = password
        if cmd == MKD:
            mkd()
        elif cmd == RMD:
            rmd()
        elif cmd == GWD:
            gwd()
        elif cmd == CWD:
            cwd()
        elif cmd == LST:
            lst()
        elif cmd == UPL:
            upl()
        elif cmd == DNL:
            dnl()
        elif cmd == RMF:
            rmf()
        elif cmd == LOGOUT:
            # self.session = logout()
            logout()

def decrypt(msg, key):
    # header = msg[slice:slice]
    # nonce = msg[slice:slice]
    # ciphertext = msg[slice:slice]
    # tag = msg[slice:slice]

    # cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # cipher.update(header)
    # plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    # return plaintext.decode('utf-8')
    return msg.decode('utf-8')

def public_decrypt(msg):
    return msg

# TODO: check hash
def correct_password(addr, pswd):
    keypair = RSA.import_key(RSA_PRIVATE_KEY)
    cipher = PKCS1_OAEP.new(keypair)

    int_pswd = int(pswd[:pswd.index('x')])
    pswd = int_pswd.to_bytes(length=512, byteorder='big')
    pswd = cipher.decrypt(pswd)
    return pswd.decode('utf-8') == PASSWORD

def sign(msg):
    # sigS(addr | g^x mod p | S | g^y mod p)
    h = SHA512.new()
    h.update(msg.encode('utf-8'))
    key = RSA.import_key(RSA_PRIVATE_KEY)
    signer = PKCS1_PSS.new(key)
    str_sig = str(int.from_bytes(signer.sign(h), 'big'))
    sig = str_sig + 'x' * (RSA_BLOCK_SIZE - len(str_sig))
    return sig

def login(netif, msg):
    sig_u = ''  # TODO: parse plainstr to get sig + authenticate

    plainstr = public_decrypt(msg).decode('utf-8')

    # parse message
    addr = plainstr[0]
    pswd = str(plainstr[2:RSA_BLOCK_SIZE+2])
    gxmodp = int(plainstr[RSA_BLOCK_SIZE+2:])

    if correct_password(addr, pswd):    # check password
        # generate diffie-hellman parameters
        dh = pyDH.DiffieHellman()
        gymodp = dh.gen_public_key()    # compute g^y mod p
        msg_to_be_signed = addr + str(gxmodp) + 'S' + str(gymodp)
        sig = sign(msg_to_be_signed)        # TODO: sign -- sigS(addr | g^x mod p | S | g^y mod p)

        # response message: [correct password | g^y mod p | sigS(addr | g^x mod p | S | g^y mod p)]
        ##                  12 bytes | 256 bytes | ?? ## TODO: pad passwords to uniform length
        rsp = CORRECT_PASSWORD + str(gymodp) + sig
        netif.send_msg(addr, rsp.encode('utf-8'))

        # wait for final response from client with salt
        status, rsp = netif.receive_msg(blocking=True)

        # get salt
        padded_salt = rsp.decode('utf-8')[1:49]
        int_salt = int(padded_salt[:padded_salt.index('x')])
        salt = int_salt.to_bytes(length=16, byteorder='big')

        # TODO: authenticate signature

        # generate session key from DH key and store
        shared_key = dh.gen_shared_key(gxmodp)  # compute shared key
        AES_key = HKDF(shared_key.encode('utf-8'), 32, salt, SHA512, 1)
        print('AES_key', AES_key)
        print('User ' + addr + ' logged in')
        return Session(addr, AES_key)
    else:
        rsp = LOGIN_FAILURE
        netif.send_msg(addr, rsp.encode('utf-8'))
        return None

# TODO: implement
def mkd():
    print('MKD operation not yet implemented')

# TODO: implement
def rmd():
    print('RMD operation not yet implemented')

# TODO: implement
def gwd():
    print('GWD operation not yet implemented')

# TODO: implement
def cwd():
    print('CWD operation not yet implemented')

# TODO: implement
def lst():
    print('LST operation not yet implemented')

# TODO: implement
def upl():
    print('UPL operation not yet implemented')

# TODO: implement
def dnl():
    print('DNL operation not yet implemented')

# TODO: implement
def rmf():
    print('RMF operation not yet implemented')

# TODO: implement
def logout():
    print('LOGOUT operation not yet implemented')
    # return None
