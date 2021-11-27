# secure-file-transfer
project completed in fulfillment of requirements for Aquincum Institute of Technology's Applied Cryptography course.

## running the program

use the following commands in separate terminal windows:
```
python3 network.py -p './network/' -a 'US' --clean
python3 server.py
python3 client.py
```

## network.py
Sets up the network in a folder called "network". Running the network.py command
highlighted in the box above will create folders based on the -a
parameters. The folders correspond to addresses of users on the network.
'U' and 'S' stand for 'user' and 'server'.
## server.py
Extremely basic right now.

Requires that first char of message received be the sender's
address so that server can send response to sender.

## client.py
Collects user input message and sends to server using netinterface.

Concatenates user's own address to message before sending so that server.py
can send a response message.

## login
Extremely rudimentary implementation supported.

Current message format: **[address | login request | password]**

Login request signified by '1'

Password is hard-coded as *password* for all users. If user submits valid password, server returns response '1'. Otherwise the 
server returns '0'.

Once a user has successfully logged in, they are given a list of commands they can use.