from spritz import Spritz
from os import urandom
from base64 import urlsafe_b64encode, urlsafe_b64decode

def pading_urlsafe_b64decode(encoded_data):
    return urlsafe_b64decode(encoded_data+b'===')

s = Spritz()
keyring = {}  # map from keyid to secret key 

def add_key(key):
    global keyring
    keyid = bytes(s.hash(key, 15))
    keyring[urlsafe_b64encode(keyid)] = key
    return urlsafe_b64encode(keyid)

def box(data, aad, keyid, nonce = urandom(12)):
    key = keyring[keyid]
    ciphertext = bytes(s.aead(
        r=32,
        M=data, 
        H=aad, 
        Z=nonce, 
        K=key
    ))
    
    # keyid.nonce.aad.ciphertext urlsafe b64
    return b'.'.join([
        keyid, 
        urlsafe_b64encode(nonce).rstrip(b'='), 
        urlsafe_b64encode(aad).rstrip(b'='), 
        urlsafe_b64encode(ciphertext).rstrip(b'='),
    ])

def unbox(msg):
    msg_key_id, msg_nonce, msg_aad, msg_ciphertext = msg.split(b'.')

    msg_ciphertext = pading_urlsafe_b64decode(msg_ciphertext)
    msg_aad = pading_urlsafe_b64decode(msg_aad)
    msg_nonce = pading_urlsafe_b64decode(msg_nonce)

    msg_data = bytes(s.aead_decrypt(
        r=32,
        C=msg_ciphertext, 
        H=msg_aad, 
        Z=msg_nonce, 
        K=keyring[msg_key_id],
    ))
    return dict(data=msg_data, aad=msg_aad, destination=msg_key_id)