###-----------------------------------------------###
# implementation of encryption operations for secure
# file transfer
###-----------------------------------------------###

from Crypto.Cipher import AES

def check_sqn(sqn_session, sqn_msg):
    return sqn_msg > sqn_session

def decrypt(msg, key):
    nonce = msg[:16]            # nonce = msg[slice:slice]          16 bytes
    header = msg[16:21]         # header = msg[slice:slice]         5 bytes
    ciphertext = msg[21:-16]    # ciphertext = msg[slice:slice]
    tag = msg[-16:]             # tag = msg[slice:slice]            16 bytes

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(header)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    addr = chr(header[0])
    cmd = chr(plaintext[0])
    if len(plaintext) == 1:
        arg = None
    else:
        arg = plaintext[1:].decode('utf-8')

    return addr, cmd, arg

def encrypt(key, header, plaintext):

    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return cipher.nonce + header + ciphertext + tag
