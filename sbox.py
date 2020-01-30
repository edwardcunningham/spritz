from spritz import Spritz
from os import urandom
from base64 import urlsafe_b64encode, urlsafe_b64decode
from yaml import safe_load
from json import loads, dumps
from getpass import getuser
from pathlib import Path

def pading_urlsafe_b64decode(encoded_data):
    return urlsafe_b64decode(encoded_data+b'===')

def padingless_urlsafe_b64encode(data):
    return urlsafe_b64encode(data).rstrip(b'=')

spritz = Spritz()
keyring = {}
# keyring = {":scope": {"current_key": ":key",
#                       "keys": {":keyid": ":key"}}}

def keyid(key):
    return padingless_urlsafe_b64encode(bytes(spritz.hash(key, 15)))

def read_scope(scope_name=getuser()):
    if scope_name.isalnum():
        with open(Path.joinpath(
            Path.home(),
            '.sbox',
            'keyring',
            f'{scope_name}.keyring',
        )) as f:
            add_scope(f.read(), scope_name)


def add_scope(scope_yaml, scope_name=getuser()):
    global keyring
    scope = safe_load(scope_yaml)
    current_key = pading_urlsafe_b64decode(scope["current_key"].encode())
    keyring[scope_name] = {
        "current_key": current_key,
        "keys": {
            keyid(key): key
            for b64_key in scope["previous_keys"]
            for key in [pading_urlsafe_b64decode(b64_key.encode())]
        }
    }
    keyring[scope_name]["keys"][keyid(current_key)]= current_key

def sbox(headers={}, data=b"", scope=getuser(), pinned_nonce_for_testing = None):
    """
    sbox a scoped encripted box

    headers sould be a string to string map utf-8 encoded
    data should be an arbatrary byte stream
    scope a string that is a vaid unix username
    nonce should never be passed in outside testing
    """
    nonce = pinned_nonce_for_testing or urandom(12)
    if scope not in keyring:
        read_scope(scope_name=scope)
    key = keyring[scope]["current_key"]
    current_keyid = keyid(key)
    headers = headers.copy()
    headers['scope']=scope # add scope to the header data

    header = dumps(headers).encode()

    ciphertext = bytes(spritz.aead(
        r=32,
        M=data,
        H=header,
        Z=nonce,
        K=key
    ))

    # keyid.nonce.header.ciphertext urlsafe b64
    return b'.'.join([
        current_keyid,
        padingless_urlsafe_b64encode(nonce),
        padingless_urlsafe_b64encode(header),
        padingless_urlsafe_b64encode(ciphertext),
    ])

def unsbox(msg, scope=getuser()):
    msg_key_id, b64_nonce, b64_header, b64_ciphertext = msg.split(b'.')

    msg_header = pading_urlsafe_b64decode(b64_header)
    msg_ciphertext = pading_urlsafe_b64decode(b64_ciphertext)

    if scope not in keyring:
        read_scope(scope_name=scope)
    key = keyring[scope]["keys"][msg_key_id]

    msg_data = bytes(spritz.aead_decrypt(
        r=32,
        C=msg_ciphertext,
        H=msg_header,
        Z=pading_urlsafe_b64decode(b64_nonce),
        K=key,
    ))
    return dict(header=loads(msg_header), data=msg_data)