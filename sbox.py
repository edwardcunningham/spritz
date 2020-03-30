from getpass import getuser
from json import loads, dumps
from os import urandom
from pathlib import Path
from spritz import Spritz
from base85 import encode85, decode85

spritz = Spritz()
keyring = {}
# keyring = {":scope": {"current_key": ":key",
#                       "keys": {":keyid": ":key"}}}

def keyid(key):
    return encode85(bytes(spritz.hash(key, 8)))

def read_scope(scope_name=getuser()):
    """
    load the scope keys from the users home directoy

    $home/.sbox/keyring/{scope_name}.keyring
    """
    if scope_name.isalnum():
        with open(Path.joinpath(
            Path.home(),
            '.sbox',
            f'{scope_name}.keyring',
        )) as f:
            add_scope(f.read(), scope_name)


def add_scope(keys, scope=getuser()):
    """
    wight space seperated b85 keys
    the first key is considerd the current_key
    
    current_key_b85
    previous_key_b85:
    previous_previous_key_b85
    """
    global keyring
    keys = keys.split()
    keyring[scope] = {
        "current_key": decode85(keys[0]),
        "keys": {
            keyid(key): key
            for b85_key in keys
            for key in [decode85(b85_key)]
        }
    }

def sbox(
        data=b'', 
        headers={}, 
        scope=getuser(), 
        pinned_nonce_for_testing = None,
    ):
    """
    sbox a scoped encripted box

    sbox(
        data: bytes, 
        headers: dict[str: str], 
        scope: str, 
        pinned_nonce_for_testing: bytes
    ) -> ciphertext: bytes

    headers sould be a string to string map utf-8 encoded
    data should be an arbatrary byte stream
    scope a string that is a vaid unix username
    nonce should never be passed in outside testing
    """
    if scope not in keyring:
        read_scope(scope_name=scope)

    current_key = keyring[scope]["current_key"]
    nonce = pinned_nonce_for_testing or urandom(12)
    headers = headers.copy()
    headers['scope']=scope # add scope to the header data
    header = dumps(headers).encode()
    ciphertext = bytes(spritz.aead(
        r=32,
        M=data,
        H=header,
        Z=nonce,
        K=current_key
    ))
    # keyid/nonce/header/ciphertext base85
    return '/'.join([
        keyid(current_key),
        encode85(nonce),
        encode85(header),
        encode85(ciphertext),
    ])

def unsbox(msg, scope=getuser()):
    """
    unsbox unseal the contence of a scoped encripted box

    unsbox(
        msg: bytes, # the tresnmited or stored ciphertext
        scope: str, # the name of the scope where the keys are
    ) -> dict(header: dict[str: str], 'data': bytes}
    """
    if scope not in keyring:
        read_scope(scope_name=scope)

    msg_key_id, b85_nonce, b85_header, b85_ciphertext = msg.split('/')
    msg_header = decode85(b85_header)
    msg_data = bytes(spritz.aead_decrypt(
        r=32,
        C=decode85(b85_ciphertext),
        H=msg_header,
        Z=decode85(b85_nonce),
        K=keyring[scope]["keys"][msg_key_id],
    ))
    return dict(header=loads(msg_header), data=msg_data)
