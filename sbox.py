from getpass import getuser
from json import loads, dumps
from os import urandom
from pathlib import Path
from spritz import Spritz
from yaml import safe_load
from base85 import encode85, decode85

spritz = Spritz()
keyring = {}
# keyring = {":scope": {"current_key": ":key",
#                       "keys": {":keyid": ":key"}}}

def keyid(key):
    return encode85(bytes(spritz.hash(key, 15)))

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
    """
    current_key: :keyb85
    previous_keys:
        - :keyb85
        - :keyb85
    """
    global keyring
    scope = safe_load(scope_yaml)
    current_key = decode85(scope["current_key"])
    keyring[scope_name] = {
        "current_key": current_key,
        "keys": {
            keyid(key): key
            for b85_key in scope["previous_keys"]
            for key in [decode85(b85_key)]
        }
    }
    keyring[scope_name]["keys"][keyid(current_key)]= current_key

def sbox(data=b"", headers={}, scope=getuser(), pinned_nonce_for_testing = None):
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
    # keyid/nonce/header/ciphertext base85
    return '/'.join([
        current_keyid,
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
    msg_key_id, b85_nonce, b85_header, b85_ciphertext = msg.split('/')

    msg_header = decode85(b85_header)
    msg_ciphertext = decode85(b85_ciphertext)

    if scope not in keyring:
        read_scope(scope_name=scope)
    key = keyring[scope]["keys"][msg_key_id]

    msg_data = bytes(spritz.aead_decrypt(
        r=32,
        C=msg_ciphertext,
        H=msg_header,
        Z=decode85(b85_nonce),
        K=key,
    ))
    return dict(header=loads(msg_header), data=msg_data)
