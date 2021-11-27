###-----------------------------------------------###
# implementation of client operations for secure
# file transfer
###-----------------------------------------------###

dst = 'S'
LOGIN_SUCCESS = '1'
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

def build_msg(addr, cmd, content):
    # TODO: add msg length, signature/MAC w/ msg sqn #, encryption, padding on fields
    return addr + cmd + content

def login(netif, addr):
    # input password in terminal
    logged_in = False

    while not logged_in:
        pswd = input('Enter password: ')

        # build login request
        ## [address | login request | password]
        msg = build_msg(addr, LOGIN, pswd)

        # send login request
        netif.send_msg(dst, msg.encode('utf-8'))

        # TODO: set timer
        # wait for server response
        status, rsp = netif.receive_msg(blocking=True)

        # TODO: parse response message for accept/reject
        login_response = rsp.decode('utf-8')

        # parse received message
        logged_in = (login_response == LOGIN_SUCCESS)
        if logged_in: return True
        print('Password incorrect. Please try again')

