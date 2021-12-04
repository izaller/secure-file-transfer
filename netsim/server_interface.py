###-----------------------------------------------###
# implementation of server operations for secure
# file transfer
###-----------------------------------------------###

import os

import pyDH
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from aes_ops import *

from session import Session

RSA_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2KLWOGq+DKVqRaDqFzyk\n4oF37h/BnJsNJrK03id3x7KdFqv6Fzx3pptX7LJW3B5ECmQqG5tUhR7x+SLsIbNv\nWokruHVe8t8S0Y84Lg4eAbqu04+51wtgbX9wHQXHRaurSZn6LbFoZynPjvoaAAFW\nOPGDsnGYMFmZPRkUuk06q0/3hak8Rg1HGY1PDrVF54VSZ1w/Obj0n7WALFCHjtir\nk8aKQUfrS1+WVpqCz2HDtKUfJl4r4Tqs/abZwrsN5S4vpqy9MplBnnin2TUviRpi\n1Qpjsl2kT8MD0hUd8aX+qEy8aCn8NahztTyICQsfYDsBpZAVK5W12bJkqjAHUCA+\nGNTnUWBcujg1cApzOT/0p0AW/W0DNFoho1jyLhRj5FXTo+pTshweUceldjkZePwn\nT3b7LecvX42V35OELC0wsY/2t46PfKJKRHHxiAoBVrmxdhYJCEsSWAZ34Pzw+nQ8\nA5pXVHJLs7LWmFjWatyNhDRNhzEcRIKLv5OXEcDaqRaR3PXAz0JhsrQfenicJksZ\nMpb2ygdZFE2HoYgSkZvcRl2FOvoD7zFEFw5kTB34lcuVt6CzJ1O3M24X9qzLUP+Y\nTmANypBbMs8w+GlaUrD9T76C8oyyOxBH7QCisf2StUMwg1+V4W8LjGD4HFXP77bv\nHlgEe5RKf3cub7hWlQRGgWcCAwEAAQ==\n-----END PUBLIC KEY-----'
RSA_PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----'
RSA_BLOCK_SIZE = 512  # using 4096 when generating key

SUCCESS = b'1'
FAILURE = b'0'
SERVER_UNAVAILABLE = b'X'

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

SERVER = './server/'

class Serverif:
    addr = ''
    path = ''
    session = None
    wd = ''
    root = ''

    def __init__(self, addr, path):
        self.addr = addr
        self.path = path

    def process_msg(self, netif, status, msg):
        # msg is received as byte string

        ## route to login TODO: fix for stop server while client is still running
        if self.session is None:
            self.session = login(netif, msg)
            self.wd = SERVER + chr(msg[0]) + '/'
            self.root = self.wd
            return

        # msg stucture: nonce (16 bytes)
        #               + header (5 bytes -- 1 byte sender addr, 4 bytes message sequence numebr)
        #               + message (cmd = 1 byte + optional arg)
        #               + tag (16 bytes)
        addr = chr(msg[16])
        sqn = int.from_bytes(msg[17:21], byteorder='big')
        if not check_sqn(self.session.sqn_rcv, sqn):
            print("Message sequence number failed check")
            rsp = build_msg('S', self.session, FAILURE)
            netif.send_msg(addr, rsp)
            return

        addr, cmd, arg = decrypt(msg, self.session.key)
        self.session.sqn_rcv = sqn  # update sqn_rcv to the value of the received sqn after successful decryption

        # check server availability
        print('Checking server availability')
        if self.session.partner != addr:
            rsp = build_msg(addr, self.session, SERVER_UNAVAILABLE)
            netif.send_msg(addr, rsp)
            self.session.sqn_snd += 1   # update sqn_snd
            print('User ' + addr + ' tried to send message, but server is in session with user ' + self.session.partner)
            return
        print('Server available.')

        if cmd == LOGIN:
            print('Login request received for user ' + addr)
            login(netif, msg)
            return

        rsp_plain = FAILURE
        if cmd == MKD:
            rsp_plain = mkd(self.wd, arg)
        elif cmd == RMD:
            rsp_plain = rmd(self.wd, arg)
        elif cmd == GWD:
            rsp_plain = gwd(self.wd)
        elif cmd == CWD:
            # self.wd = cwd(self.wd, self.session.key, arg)
            self.wd, rsp_plain = cwd(self.wd, arg)
        elif cmd == LST:
            rsp_plain = lst(self.wd, arg)
        elif cmd == UPL:
            rsp_plain = upl()
        elif cmd == DNL:
            rsp_plain = dnl(self.wd, arg)
        elif cmd == RMF:
            rsp_plain = rmf(self.wd, arg)
        elif cmd == LOGOUT:
            # self.session = logout()
            # need to set session to None and wd to ''
            rsp_plain = logout()

        rsp = build_msg(addr, self.session, rsp_plain)
        netif.send_msg(addr, rsp)
        self.session.sqn_snd += 1

def build_msg(addr, session, arg):
    header = addr.encode('utf-8') + (session.sqn_snd + 1).to_bytes(length=4, byteorder='big')  # header: addr + msn (5 bytes)
    return encrypt(session.key, header, arg)

# TODO: check hash
def correct_password(addr, pswd):
    keypair = RSA.import_key(RSA_PRIVATE_KEY)
    cipher = PKCS1_OAEP.new(keypair)
    pswd = cipher.decrypt(pswd)
    return pswd.decode('utf-8') == PASSWORD

def sign(msg):
    # sigS(addr | g^x mod p | S | g^y mod p)
    h = SHA512.new()
    h.update(msg.encode('utf-8'))
    key = RSA.import_key(RSA_PRIVATE_KEY)
    signer = PKCS1_PSS.new(key)
    return signer.sign(h)

def login(netif, msg):

    # parse message
    addr = chr(msg[0])
    pswd = msg[2:RSA_BLOCK_SIZE+2]
    gxmodp = int.from_bytes(msg[-272:-16], byteorder='big')
    salt = msg[-16:]

    if correct_password(addr, pswd):    # check password
        # generate diffie-hellman parameters
        dh = pyDH.DiffieHellman()
        gymodp = dh.gen_public_key()    # compute g^y mod p
        msg_to_be_signed = addr + str(gxmodp) + 'S' + str(gymodp)
        sig = sign(msg_to_be_signed)

        # response message: [correct password | g^y mod p | sigS(addr | g^x mod p | S | g^y mod p)]
        ##                  12 bytes | 256 bytes | ??
        rsp = SUCCESS + gymodp.to_bytes(length=256, byteorder='big') + sig
        netif.send_msg(addr, rsp)

        # generate shared key from Diffie-Hellman parameters
        shared_key = dh.gen_shared_key(gxmodp)  # compute shared key

        # generate AES key with HKDF using shared key and salt
        AES_key = HKDF(shared_key.encode('utf-8'), 32, salt, SHA512, 1)

        print('User ' + addr + ' logged in')
        return Session(addr, AES_key)
    else:
        netif.send_msg(addr, FAILURE)
        return None

def mkd(wd, dirname):
    if not os.path.exists(wd + dirname):
        os.mkdir(wd + dirname)
        return SUCCESS
    else:
        return FAILURE

def rmd(wd, dirname):
    if dirname == '.': return FAILURE
    if os.path.exists(wd + dirname):
        os.rmdir(wd + dirname)
        return SUCCESS
    else:
        return FAILURE

def gwd(wd):
    # send wd to client
    return SUCCESS + wd.encode('utf-8')

# TODO: implement -- backwards/forwards functionality
def cwd(wd, dirname):
    if os.path.exists(wd + dirname):
        return wd + dirname, SUCCESS
    # print('CWD operation not yet implemented')
    return wd, FAILURE

def lst(wd, dirname):
    if os.path.exists(wd + dirname):
        files = '\n'
        for r in os.listdir(wd + dirname):
            files += r + '\n'
        return SUCCESS + files.encode('utf-8')
    return FAILURE

# TODO: implement
def upl():
    print('UPL operation not yet implemented')
    return FAILURE

def dnl(wd, fname):
    if os.path.exists(wd + fname):
        f = '\n' + open(wd + fname, 'r').read() + '\n'
        return SUCCESS + f.encode('utf-8')
    return FAILURE

def rmf(wd, fname):
    if os.path.exists(wd + fname):
        os.remove(wd + fname)
        return SUCCESS
    return FAILURE

# TODO: implement
def logout():
    print('LOGOUT operation not yet implemented')
    return FAILURE
    # return None
