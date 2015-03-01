# spritz

[Spritz — a spongy RC4-like stream cipher and hash function](http://people.csail.mit.edu/rivest/pubs/RS14.pdf) (Ronald L. Rivest and Jacob C. N. Schuld, 2014)

This is a simple Python implementation of Spritz, a redesigned version of the RC4 stream cipher recently published by Rivest and Schuld, which addresses many of the shortcomings that have been identified in RC4.


#### Encryption

```python
from spritz import Spritz
import binascii

spritz = Spritz()

K = bytearray('password')
M = bytearray('Hello world!')
C = spritz.encrypt(K, M)

print binascii.hexlify(C)

# Decryption
M = spritz.decrypt(K, C)
```

### Hash

Since Spritz is a sponge-like function, it can also be used to produce cryptographic hashes of an arbitrary length.

```python
M = bytearray('content to hash')
H = spritz.hash(M, 32)

print binascii.hexlify(H)
```
