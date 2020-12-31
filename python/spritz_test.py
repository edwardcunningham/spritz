from spritz import Spritz
import binascii

def test(input, output, result):
    print('Input: %s, Output: %s - %s' % (input, output, 'PASSED' if output == result else 'FAILED'))

spritz = Spritz()

print ('// Test basic Spritz output test vectors:')

output_test_vectors = {
    b'ABC': b'779a8e01f9e9cbc0',
    b'spam': b'f0609a1df143cebf',
    b'arcfour': b'1afa8b5ee337dbc7'
}

for input, result in output_test_vectors.items():
    spritz.initialise_state()
    spritz.absorb(bytearray(input))
    output = binascii.hexlify(spritz.squeeze(8))
    test(input, output, result)

print()
print ('// Test Spritz hash test vectors:')

hash_test_vectors = {
    b'ABC': b'028fa2b48b934a18',
    b'spam': b'acbba0813f300d3a',
    b'arcfour': b'ff8cf268094c87b9'
}

for input, result in hash_test_vectors.items():
    output = binascii.hexlify(spritz.hash(bytearray(input), 32))
    test(input, output[:16], result)

print()
print ('// Encryption demo:')

key = bytearray(b'password')
message = bytearray(b'Hello world!')
output = spritz.encrypt(key, message)
print (binascii.hexlify(output))
print()

print ('// Decryption demo:')
print (spritz.decrypt(key, output))
