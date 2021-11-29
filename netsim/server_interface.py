###-----------------------------------------------###
# implementation of server operations for secure
# file transfer
###-----------------------------------------------###

import pyDH
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from session import Session

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

        # TODO:
        ## decrypt w private key and route to login
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

        # get message command type and argument
        cmd = str(plainstr[1])

        # if cmd == LOGIN:
        #     print('Login request received for user ' + addr)
        #     # pswd = str(plainstr[2:10])
        #     # gxmodp = int(plainstr[10:])     # TODO: parse message and get g^x mod p
        #     # sig_u = ''  # TODO: authenticate sig (possibly before this in the function)
        #     # self.session = login(netif, addr, pswd, gxmodp)     # arg = password
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
    return pswd == PASSWORD

def login(netif, msg):
    plainstr = public_decrypt(msg).decode('utf-8')

    # parse message
    addr = plainstr[0]
    pswd = str(plainstr[2:10])
    gxmodp = int(plainstr[10:])

    sig_u = ''  # TODO: authenticate sig (possibly before this in the function)

    if correct_password(addr, pswd):    # check password
        # generate diffie-hellman parameters
        dh = pyDH.DiffieHellman()
        gymodp = dh.gen_public_key()    # compute g^y mod p

        sig = ''        # TODO: sign -- sigS(addr | g^x mod p | S | g^y mod p)

        # response message: [correct password | g^y mod p | sigS(addr | g^x mod p | S | g^y mod p)]
        ##                  12 bytes | 256 bytes | ?? ## TODO: pad passwords to uniform length
        rsp = CORRECT_PASSWORD + str(gymodp) + sig
        netif.send_msg(addr, rsp.encode('utf-8'))

        # wait for final response from client with salt
        status, rsp = netif.receive_msg(blocking=True)
        salt = rsp[1:17]

        # TODO: authenticate signature
        shared_key = dh.gen_shared_key(gxmodp)  # compute shared key
        # TODO: generate session key from DH key and store
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