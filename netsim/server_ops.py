###-----------------------------------------------###
# implementation of server operations for secure
# file transfer
###-----------------------------------------------###

LOGIN_SUCCESS = '1'
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

def process_msg(netif, status, msg, LOGGED_IN_USER):
    # TODO: (actually) decode message
    decoded_msg = msg.decode('utf-8')

    # get sender
    addr = decoded_msg[0]

    # check server availability
    print('Checking server availability.\nLogged in user: ' + (LOGGED_IN_USER or 'None') + '\nRequest from: ' + addr)
    if LOGGED_IN_USER is not None and LOGGED_IN_USER != addr:
        rsp = SERVER_UNAVAILABLE
        netif.send_msg(addr, rsp.encode('utf-8'))
        print('User ' + addr + ' tried to send message, but server is in session with user ' + LOGGED_IN_USER)
        return LOGGED_IN_USER
    LOGGED_IN_USER = addr

    # get message command type and argument
    cmd = decoded_msg[1]
    arg = decoded_msg[2:]

    if cmd == LOGIN:
        print('Login request received for user ' + addr)
        login(netif, addr, arg)     # arg = password
    elif cmd == MKD:
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
        # LOGGED_IN_USER = None

    return LOGGED_IN_USER


# TODO: check hash
def correct_password(addr, pswd):
    return pswd == PASSWORD


def login(netif, addr, pswd):
    if correct_password(addr, pswd):
        rsp = LOGIN_SUCCESS
        netif.send_msg(addr, rsp.encode('utf-8'))
        print('User ' + addr + ' logged in')
    else:
        rsp = LOGIN_FAILURE
        netif.send_msg(addr, rsp.encode('utf-8'))


def mkd():
    print('MKD operation not yet implemented')


def rmd():
    print('RMD operation not yet implemented')


def gwd():
    print('GWD operation not yet implemented')


def cwd():
    print('CWD operation not yet implemented')


def lst():
    print('LST operation not yet implemented')


def upl():
    print('UPL operation not yet implemented')


def dnl():
    print('DNL operation not yet implemented')


def rmf():
    print('RMF operation not yet implemented')


def logout():
    print('LOGOUT operation not yet implemented')

