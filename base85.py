import os
import json

# the chars that are 1 byte in a JSON string
base95_alphabet = ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~'

# drop "\"\\" chr[34, 92]
base93_alphabet = " !#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~" 

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

# regex /[!#%&(*+\-.0-[^-|~]+/

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
        if integer >> 32:
            return OverflowError(f"{integer} > uint32_max")
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
    assert passed, f"{new_string}, {new_buffer}"
    print('.', end='')

def run_tests():
    test(b'\xff\x00\x00\x00', 'zzB&!')
    test(b'\xff',             'zz')
    test(b'\xff\xff\x00\x00', '{>T+!')
    test(b'\xff\xff',         '{>T')
    test(b'\xff\xff\xff\x00', '{>_0!')
    test(b'\xff\xff\xff',     '{>_0')
    test(b'\xff\xff\xff\xff', '{>_3!')

    test(b'\xff\xff\xff\xff\xff\x00',         '{>_3!zzB')
    test(b'\xff\xff\xff\xff\xff',             '{>_3!zz')
    test(b'\xff\xff\xff\xff\xff\xff',         '{>_3!{>T')
    test(b'\xff\xff\xff\xff\xff\xff\xff',     '{>_3!{>_0')
    test(b'\xff\xff\xff\xff\xff\xff\xff\xff', '{>_3!{>_3!')

    test(b'!\xad\x97\x96\\\xb9O\x1bek\xc9\x87\x9d:#\xe5b\xe5\x81d\r\xd7ofW\x8fE\xf5\xde\x9eJ\x89',
        '1o(.{Dm0_RGYeJIYT>#_Fkh5U(M2T7C3%nIpUcDz')

    test(
        b"Man is distinguished, not only by his reason, but by this singul"
        b"ar passion from other animals, which is a lust of the mind, that"
        b" by a perseverance of delight in the continued and indefatigable"
        b" generation of knowledge, exceeds the short vehemence of any car"
        b"nal pleasure.",
        "?rywfHtjJ3HtmH7JP101L-n2y56PpQLBMRDIrF4:Mx&l=L!2R=FB<F.56PJKLBM(B"
        "1K^@8L!2UBJP104FB0Q6FB<R-Jn3d6Kk;mAJnnb-Kbmm4Ht4?xL#GM`HVI{q1JMuD"
        "F9HH5L0*UIGn~85GQaq-JOj@FLJ20.1Ie[CF9HT%Kkan>GZJ9{FyEl&Gn|^yIpcTy"
        "LBM@>1K^@41InD3LJ;_>GXtwtJOit-JOlBrFBE9zF@L(i1J;>+GZJ:&HtFt9Jm@23"
        "JP{h>GXwLj56PSQFyH:fL!2XBGQb*3JnZyHM(MD~J4XZxGQaw+1IZ5;1Imq%JOOE-"
        "K2?.wL08S=5k")

    test(
        b"\x00\t\x98b\x0f\xc7\x99C\x1f\x85\x9a$/C\x9b\x05?\x01\x9b\xe6N\xbf"
        b"\x9c\xc7^}\x9d\xa8n;\x9e\x89}\xf9\x9fj\x8d\xb7\xa0K\x9du\xa1,\xad"
        b"3\xa2\r\xbc\xf1\xa2\xee\xcc\xaf\xa3\xcf\xdcm\xa4\xb0\xec+\xa5\x91"
        b"\xfb\xe9\xa6r",
        "!#%&(*+-.0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[^_`abcdefghij"
        "klmnopqrstuvwxyz{|~")

if __name__ == "__main__":
    run_tests()
    b = os.urandom(32)
    s = encode85(b)
    assert decode85(s)==b
    print()
    print(json.dumps(s))
    print(json.dumps(encode85(os.urandom(8))))