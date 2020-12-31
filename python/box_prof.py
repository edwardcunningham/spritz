import cProfile
from box import add_key, box, unbox

cProfile.run(r"""
data = b'this is a test payload'
aad = b'this is metadata'
destination = b'0fuc5Q3IDEorUROn0MeF'
nonce = b'R\xa1o$\xb2\xb3\x1d\xba\xb8\x9b!\xc0'
# keyid.nonce.aad.ciphertext urlsafe b64
ciphertext = b'0fuc5Q3IDEorUROn0MeF.UqFvJLKzHbq4myHA.dGhpcyBpcyBtZXRhZGF0YQ.wdMpLx-cfTGM0_JeCRSBqtSb3i1wfXTPEo2JzQ3wVyzZTJgYoKIOaoodC7RgDbs3kn71P6xK'

print(destination == add_key(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'))
print(box(keyid=destination, header=aad,  data=data, nonce=nonce) == ciphertext)
print(unbox(ciphertext) == {'data': data, 'header': aad, 'keyid': destination})
""", sort=2)