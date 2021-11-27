###-----------------------------------------------###
# implementation of server operations for secure
# file transfer
###-----------------------------------------------###

LOGIN_SUCCESS = 'accepted'
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

def process_msg(netif, status, msg):
    # decode message
    decoded_msg = msg.decode('utf-8')

    # TODO: parse message
    # get sender
    addr = decoded_msg[0]

    # get message type
    m_type = decoded_msg[1]
    msg_content = decoded_msg[2:]

    if m_type == LOGIN:
        print('Login request received for user ' + addr)
        login(netif, addr, msg_content)

    # rsp = 'message received'
    # if status:
    #     netif.send_msg(addr, rsp.encode('utf-8'))
    #     print('message sent')
    # return

def login(netif, addr, pswd):
    if pswd == PASSWORD:
        rsp = '1'
        netif.send_msg(addr, rsp.encode('utf-8'))
        print('User ' + addr + ' logged in')
    else:
        rsp = '0'
        netif.send_msg(addr, rsp.encode('utf-8'))
