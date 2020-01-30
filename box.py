from spritz import Spritz
from os import urandom
from base64 import urlsafe_b64encode, urlsafe_b64decode

def pading_urlsafe_b64decode(encoded_data):
    return urlsafe_b64decode(encoded_data+b'===')

def padingless_urlsafe_b64encode(data):
    return urlsafe_b64encode(data).rstrip(b'=')

s = Spritz()
keyring = {}
# map from keyid to secret key
# any aditional preamiters like nonce_size cheacksum_size or algorithem
# should be looked up by the keyID
# the keyID is both the key rotation tratogy and the agorithem rotation stratogey
# that is why it is first

def add_key(key):
    global keyring
    keyid = urlsafe_b64encode(bytes(s.hash(key, 15)))
    keyring[keyid] = key
    return keyid

def box(keyid, header, data, nonce = urandom(12)):
    key = keyring[keyid]
    ciphertext = bytes(s.aead(
        r=32,
        M=data,
        H=header,
        Z=nonce,
        K=key
    ))
    
    # keyid.nonce.header.ciphertext urlsafe b64
    return b'.'.join([
        keyid, 
        padingless_urlsafe_b64encode(nonce),
        padingless_urlsafe_b64encode(header),
        padingless_urlsafe_b64encode(ciphertext),
    ])

def unbox(msg):
    msg_key_id, b64_nonce, b64_header, b64_ciphertext = msg.split(b'.')

    msg_header = pading_urlsafe_b64decode(b64_header)
    msg_ciphertext = pading_urlsafe_b64decode(b64_ciphertext)

    msg_data = bytes(s.aead_decrypt(
        r=32,
        C=msg_ciphertext,
        H=msg_header,
        Z=pading_urlsafe_b64decode(b64_nonce),
        K=keyring[msg_key_id],
    ))
    return dict(keyid=msg_key_id, header=msg_header, data=msg_data)