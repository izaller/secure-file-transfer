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
import sys

sys.path.insert(0, 'server')

from password_dictionary import password_dictionary

from session import Session

RSA_BLOCK_SIZE = 512  # using 4096 when generating key

SUCCESS = b'1'
FAILURE = b'0'
SERVER_UNAVAILABLE = b'X'
FORCED_LOGOUT = b'2'

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

        ## route to login
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
            self.wd, rsp_plain = cwd(self.root, self.wd, arg)
        elif cmd == LST:
            rsp_plain = lst(self.wd, arg)
        elif cmd == UPL:
            rsp_plain = upl(self.wd, arg)
        elif cmd == DNL:
            rsp_plain = dnl(self.wd, arg)
        elif cmd == RMF:
            rsp_plain = rmf(self.wd, arg)
        elif cmd == LOGOUT:
            rsp_plain = logout()

        rsp = build_msg(addr, self.session, rsp_plain)
        netif.send_msg(addr, rsp)
        self.session.sqn_snd += 1

        if cmd == LOGOUT:
            self.session = None
            self.wd = ''

    def force_logout(self, netif):
        if self.session:
            rsp = build_msg('S', self.session, FORCED_LOGOUT)
            netif.send_msg(self.session.partner, rsp)
            self.session = None
        return

def build_msg(addr, session, arg):
    header = addr.encode('utf-8') + (session.sqn_snd + 1).to_bytes(length=4, byteorder='big')  # header: addr + msn (5 bytes)
    return encrypt(session.key, header, arg)

## read in password hash for the given address
def correct_password(addr, pswd):
    kfile = open('server_keys/rsa-encryption-keypair.pem', 'r')
    keypairstr = kfile.read()
    kfile.close()

    keypair = RSA.import_key(keypairstr)
    cipher = PKCS1_OAEP.new(keypair)
    pswd = cipher.decrypt(pswd)
    
    # hash pswd and check for equality
    h = SHA512.new()
    h.update(pswd)
    hash = h.hexdigest()

    # checks password_dictionary in server folder which contains hashes for passwordX (A to Z)
    return hash == password_dictionary[addr]

def sign(msg):
    # sigS(addr | g^x mod p | S | g^y mod p)
    h = SHA512.new()
    h.update(msg.encode('utf-8'))

    kfile = open('server_keys/rsa-sig-keypair.pem', 'r')
    keypairstr = kfile.read()
    kfile.close()

    key = RSA.import_key(keypairstr)
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

# Works backwords/forwards if client inputs complete pathname, eg: ./server/U/dirname
def cwd(root, wd, dirname):
    if dirname[:11] != root:
        return wd, FAILURE
    if os.path.exists(dirname):
        return dirname, SUCCESS
    return wd, FAILURE

def lst(wd, dirname):
    if os.path.exists(wd + dirname):
        files = '   '
        for r in os.listdir(wd + dirname):
            files += r + '  '
        return SUCCESS + files.encode('utf-8')[:-2]
    return FAILURE

def upl(wd, arg):
    fname = arg[:arg.index('\n')]
    msg = arg[len(fname) + 1:].encode('utf-8')
    fname = fname[fname.rfind('/') + 1:]
    with open(wd + '/' + fname, 'wb') as f: f.write(msg)
    return SUCCESS

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

def logout():
    return SUCCESS
