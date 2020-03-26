import os
import json

# the chars that are 1 byte in a JSON string
base95_alphabet = ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~'

# drop "\"\\" chr[34, 92]
base93_alphabet = " !#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~" 

# drop " ',./:[]" chr[32, 39, 44, 46, 47, 58, 91, 93]
# drop ' '  32 since it is ambigus with tab 
# drop '"'  34 since it is a string container
# drop '$'  36 since it is not on all keybords
# drop "'"  39 since it is a string container
# drop ')'  41 since it implies grouping
# drop ','  44 since it is a separator
# drop '/'  47 since it is a separator
# drop '\'  92 since it is a escape character
# drop ']'  93 since it implies grouping
# drop '}' 125 since it implies grouping
base85_alphabet = "!#%&(*+-.0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[^_`abcdefghijklmnopqrstuvwxyz{|~" 


integer2character85 = base85_alphabet
character2integer85 = {character: index for index, character in enumerate(base85_alphabet)}

def encode85(buffer):
    pad = (-(len(buffer) % -4))
    buffer = buffer + b'\x00'*pad
    encoded = [''] * ((len(buffer)//4)*5)
    for i in range(0, len(buffer)//4):
        integer = ((buffer[4 * i + 0] << 24)|
                   (buffer[4 * i + 1] << 16)|
                   (buffer[4 * i + 2] << 8 )|
                   (buffer[4 * i + 3] << 0 ))
        encoded[5 * i + 0] = integer2character85[integer // (85**4) % 85]
        encoded[5 * i + 1] = integer2character85[integer // (85**3) % 85]
        encoded[5 * i + 2] = integer2character85[integer // (85**2) % 85]
        encoded[5 * i + 3] = integer2character85[integer // (85**1) % 85]
        encoded[5 * i + 4] = integer2character85[integer // (85**0) % 85]
    return ''.join(encoded)[:len(encoded)-pad]

def decode85(string):
    pad = (-(len(string) % -5))
    string = string + '~'*pad
    buffer = bytearray(len(string) // 5 * 4)
    for i in range(0, len(string) // 5):
        integer = (character2integer85[string[i * 5 + 0]] * (85 ** 4) +  
                   character2integer85[string[i * 5 + 1]] * (85 ** 3) +
                   character2integer85[string[i * 5 + 2]] * (85 ** 2) +
                   character2integer85[string[i * 5 + 3]] * (85 ** 1) +
                   character2integer85[string[i * 5 + 4]] * (85 ** 0))
        buffer[i * 4 + 0] = integer >> 24 & 0xff
        buffer[i * 4 + 1] = integer >> 16 & 0xff
        buffer[i * 4 + 2] = integer >>  8 & 0xff
        buffer[i * 4 + 3] = integer >>  0 & 0xff
    return bytes(buffer[:len(buffer)-pad])

def test(buffer, string):
    new_string = encode85(buffer)
    new_buffer = decode85(string)
    passed = (string == new_string and buffer == new_buffer)
    # print('pass' if passed else 'fail', buffer, string, '\n    ', new_buffer, new_string)
    assert passed
    print('.', end='')

test(b'\xff\x00\x00\x00', '{{B%!')
test(b'\xff',             '{{')
test(b'\xff\xff\x00\x00', '|>T)!')
test(b'\xff\xff',         '|>T')
test(b'\xff\xff\xff\x00', '|>`-!')
test(b'\xff\xff\xff',     '|>`-')
test(b'\xff\xff\xff\xff', '|>`2!')

test(b'\xff\xff\xff\xff\xff\x00',         '|>`2!{{B')
test(b'\xff\xff\xff\xff\xff',             '|>`2!{{')
test(b'\xff\xff\xff\xff\xff\xff',         '|>`2!|>T')
test(b'\xff\xff\xff\xff\xff\xff\xff',     '|>`2!|>`-')
test(b'\xff\xff\xff\xff\xff\xff\xff\xff', '|>`2!|>`2!')

test(b'!\xad\x97\x96\\\xb9O\x1bek\xc9\x87\x9d:#\xe5b\xe5\x81d\r\xd7ofW\x8fE\xf5\xde\x9eJ\x89',
     '0p&+|Dn-`RGYfJIYT>#`Fli4U&M1T6C2$oIqUdD{')

b = os.urandom(32)
s = encode85(b)
assert decode85(s)==b
print()
print(json.dumps(s))
print(json.dumps(encode85(os.urandom(8))))