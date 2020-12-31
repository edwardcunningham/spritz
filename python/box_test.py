from box import add_key, box, unbox
from os import urandom

def assert_eq(a, b):
    if a == b:
        print('.',  end="")
    else:
        print("Fail\n\t{}\n\t{}".format(a,b))


data = b'this is a test payload'
aad = b'this is metadata'
destination = b'0fuc5Q3IDEorUROn0MeF'
nonce = b'R\xa1o$\xb2\xb3\x1d\xba\xb8\x9b!\xc0'
# keyid.nonce.aad.ciphertext urlsafe b64
ciphertext = b'.'.join((
    b'0fuc5Q3IDEorUROn0MeF',
    b'UqFvJLKzHbq4myHA',
    b'dGhpcyBpcyBtZXRhZGF0YQ',
    b'wdMpLx-cfTGM0_JeCRSBqtSb3i1wfXTPEo2JzQ3wVyzZTJgYoKIOaoodC7RgDbs3kn71P6xK',
))

assert_eq(destination, add_key(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'))
assert_eq(box(keyid=destination, header=aad,  data=data, nonce=nonce),
          ciphertext)
assert_eq(unbox(ciphertext),
          {'data': data, 'header': aad, 'keyid': destination})

rdata = urandom(1111)
raad = urandom(333)
rdestination = add_key(urandom(32))
rciphertext = box(data=rdata, header=raad, keyid=rdestination)
assert_eq(unbox(rciphertext),
    {'data': rdata, 'header': raad, 'keyid': rdestination})
