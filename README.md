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

Using netinterface, waits for message to be received then
sends response "message received" back to sender.

Requires that first char of message received be the sender's
address so that server can send response to sender.
## client.py
Collects user input message and sends to server using netinterface.

Concatenates user's own address to message before sending so that server.py
can send a response message.

Waits for server response and then asks client if they want to continue.