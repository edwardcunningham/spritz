from sbox import add_scope, sbox, unsbox, keyid, padingless_urlsafe_b64encode
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
# keyid.nonce.aad.ciphertext urlsafe b64
ciphertext = (
    b'0fuc5Q3IDEorUROn0MeF.'  # keyid
    b'UqFvJLKzHbq4myHA.'  # nonce
    b'eyJtZXRhZGF0YSI6ICJ0aGlzIGlzIG1ldGFkYXRhIiwgInNjb3BlIjogIm15X3Njb3BlIn0.'  # headers
    b'FopoviWBT71ktZjKOwH2mjJWWD1pzgbiO7qSrazu7MPlH0vfobFpxCGyei6ikXsQPd-aPMKQ'  # data
)
scope_yaml='''
    current_key: YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE
    previous_keys:
        - cHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHA
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
rmetadata = padingless_urlsafe_b64encode(urandom(333)).decode()
rkey = urandom(32)
rkeyid = keyid(rkey)
rdestination = padingless_urlsafe_b64encode(urandom(32)).decode()

add_scope(
    scope_yaml=f'''
        current_key: {padingless_urlsafe_b64encode(rkey)}
        previous_keys:
            - cHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHA
    ''',
    scope_name=rdestination,
)

rciphertext = sbox(scope=rdestination, headers={"metadata": rmetadata},  data=rdata)
assert_eq(
    unsbox(rciphertext, scope=rdestination),
    {'header': {'metadata': rmetadata, 'scope': rdestination},
     'data': rdata},
)
