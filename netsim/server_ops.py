###-----------------------------------------------###
# implementation of server operations for secure
# file transfer
###-----------------------------------------------###

LOGIN_SUCCESS = '1'
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
    # decode message
    decoded_msg = msg.decode('utf-8')
    print(decoded_msg)

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

    # get message type
    m_type = decoded_msg[1]
    msg_content = decoded_msg[2:]

    if m_type == LOGIN:
        print('Login request received for user ' + addr)
        login(netif, addr, msg_content)
    elif m_type == MKD:
        print('MKD operation not yet implemented')
    elif m_type == RMD:
        print('RMD operation not yet implemented')
    elif m_type == GWD:
        print('GWD operation not yet implemented')
    elif m_type == CWD:
        print('CWD operation not yet implemented')
    elif m_type == LST:
        print('LST operation not yet implemented')
    elif m_type == UPL:
        print('UPL operation not yet implemented')
    elif m_type == DNL:
        print('DNL operation not yet implemented')
    elif m_type == RMF:
        print('RMF operation not yet implemented')
    elif m_type == LOGOUT:
        print('LOGOUT operation not yet implemented')

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
        rsp = '0'
        netif.send_msg(addr, rsp.encode('utf-8'))
