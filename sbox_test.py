from sbox import add_scope, sbox, unsbox, keyid, encode85
from os import urandom

def assert_eq(a, b):
    if a == b:
        print('.',  end="")
    else:
        print("Fail\n\t{}\n\t{}".format(a,b))

# test data
data = b'this is a test payload'
metadata = 'this is metadata'
destination = 'my_scope'
nonce = b'R\xa1o$\xb2\xb3\x1d\xba\xb8\x9b!\xc0'
# keyid/nonce/aad/ciphertext base 85
# len ciphertext = 4/3 * datasize + 39 bytes
# e.g 1kb -> 1405 byte
ciphertext = (
    'V8fVY5pbK;X%8luho4p/'  # keyid len=19
    'AVG#YbKsXgdC:a_/'  # nonce len=15
    'NWuBBLIGeoLIEFY1BswFHtjJ8L!2C8LIGeoLIEFK1Bst@JnH>99bw^hN!j_*JnH>9O5/'  # headers len ceil(5*len/4) grater
    'X>zSLMy8M0W3cc*`%8wPn^7?JT<k#eU=^BYZrU;V{3y!|_rjr-tZ{F6i^!K@wo:2SzXR'  # data len ceil(5*len/4) grater
)

scope_yaml='''
    current_key: Ctl.s9OPut#r(dxmM%Yak3*UD_HZ3`TZDrs*sGpH
    previous_keys:
        - t(<p&@f(Fj2>#FP(p7KSKjZakCTXjKhll=`:2z80
    '''

#tests
add_scope(scope_yaml=scope_yaml, scope_name=destination)

assert_eq(sbox(
    scope=destination,
    headers={"metadata": metadata},
    data=data,
    pinned_nonce_for_testing=nonce
),ciphertext)

assert_eq(
    unsbox(ciphertext, scope=destination),
    {'header': {'metadata': metadata, 'scope': destination},
     'data': data},
)

rdata = urandom(1111)
rmetadata = encode85(urandom(333))
rkey = urandom(32)
rkeyid = keyid(rkey)
rdestination = encode85(urandom(32))

add_scope(
    scope_yaml=f'''
        current_key: "{encode85(rkey)}"
        previous_keys:
            - t(<p&@f(Fj2>#FP(p7KSKjZakCTXjKhll=`:2z80
    ''',
    scope_name=rdestination,
)

rciphertext = sbox(scope=rdestination, headers={"metadata": rmetadata},  data=rdata)
assert_eq(
    unsbox(rciphertext, scope=rdestination),
    {'header': {'metadata': rmetadata, 'scope': rdestination},
     'data': rdata},
)
