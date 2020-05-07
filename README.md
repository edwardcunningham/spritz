# sbox

Sbox is a format and api for encripted data.
each sbox or scoped box is a blob encripted to a scope
any other member of that scope can unencript or unbox to
recover the mesige

the format of the sbox is keyid/nonce/header/ciphertext
* each segment is bef(base eighty five)
* the keyid is the id by witch to look up encription key (64 bits)
  * encription key is 256 bit
* the nonce is a randomly chosen number (96 bits)
* the header is a bytearray
  * this is authenticated but not encripted 
* the ciphertext is a bytearry
  * this is authenticated and encripted

## .sbox/scope.keyring
the keyring file is formated as a testfile
* each line seperated by "\n" is a key
  * each key can be used to decript boxes
* each line is a base85 encoded key folowed with an optional spase and comment
* empty lines will be ignored
* the last line is the curent key
  * this is the key that is used to encryipt new boxes

a box is considered to be "in" a scope if the key that was used to
encript it is in the keyring
```
bef_encoded_secret_key1 some coments
bef_encoded_secret_key2 some other comment
```

we store the keyring in a file in the home diirectory 
"~/.sbox/scope_name.keyring" but it could be stored anywhere 
you can store a maping from a scope_name to a string

## sbox api
* load the keys
  * add_scope(keyring_string, scope_name)

* box
  * ciphertext = sbox(data)
  * ciphertext = sbox(data, scope)
  * ciphertext = sbox(data, headers)
  * ciphertext = sbox(data, headers, scope)

* unbox
  * data, headers = unsbox(data)
  * data, headers = unsbox(data, headers)

```rust
fn sbox_with_headers_and_scope(
  data:    &[u8],
  headers: HashMap<String, String>,
  scope:   &str,
) -> String;

fn unsbox_with_scope(
  msg:   &str,
  scope: &str
) -> Result<(String, Vec<u8>), &'static str>;
```



# spritz

[Spritz — a spongy RC4-like stream cipher and hash function](http://people.csail.mit.edu/rivest/pubs/RS14.pdf) (Ronald L. Rivest and Jacob C. N. Schuld, 2014)

This is a simple Python and Rust implementation of Spritz,
a redesigned version of the RC4 stream cipher recently 
published by Rivest and Schuld, which addresses many of 
the shortcomings that have been identified in RC4.

#### hash
```rust
// a crpytografic hash function
 fn hash(m: &[u8], r: u8) -> Vec<u8>
```

#### Autenticated Encription with Asoseated Data

  * key
    * u8 the secret matereal for the encription
    * defult length 256 bits
  * nonce
    * u8 a random number
    * defult length 96 bits
  * header
    * u8
    * defult utf-8 encoded json
    * could be any raw bytes this is up to the user
  * message
    * u8 raw bytes

```rust
 //autenticated encription with asoseated data
 fn aead(
  key:      &[u8],
  nonce:    &[u8],
  header :  &[u8],
  message : &[u8],
  authentication_tag_length: u8
) -> Vec<u8> 

 //autenticated decription with asoseated data
fn aead_decrypt(
  key:      &[u8],
  nonce:    &[u8],
  header :  &[u8],
  message : &[u8],
  authentication_tag_length: u8
) -> Result<Vec<u8>, &'static str> 
```

### bef (Base Eighty Five)

map from charicters to intagers 
```py
{ 0: "!",  1: "#",  2: "%",  3: "&",  4: "(",  5: "*",  6: "+",  7: "-", 
  8: ".",  9: "0", 10: "1", 11: "2", 12: "3", 13: "4", 14: "5", 15: "6",
 16: "7", 17: "8", 18: "9", 19: ":", 20: ";", 21: "<", 22: "=", 23: ">",
 24: "?", 25: "@", 26: "A", 27: "B", 28: "C", 29: "D", 30: "E", 31: "F",
 32: "G", 33: "H", 34: "I", 35: "J", 36: "K", 37: "L", 38: "M", 39: "N",
 40: "O", 41: "P", 42: "Q", 43: "R", 44: "S", 45: "T", 46: "U", 47: "V",
 48: "W", 49: "X", 50: "Y", 51: "Z", 52: "[", 53: "^", 54: "_", 55: "`",
 56: "a", 57: "b", 58: "c", 59: "d", 60: "e", 61: "f", 62: "g", 63: "h",
 64: "i", 65: "j", 66: "k", 67: "l", 68: "m", 69: "n", 70: "o", 71: "p",
 72: "q", 73: "r", 74: "s", 75: "t", 76: "u", 77: "v", 78: "w", 79: "x",
 80: "y", 81: "z", 82: "{", 83: "|", 84: "~"}
 ```

A aside on the choise of the 85 caricters
we chose carictersn that are a single byte in a JSON string
this allows b85 data to be sent between systems that can deal with json

```py
# the chars that are printable ascci
base95_alphabet = ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~'

# the chars that are 1 byte in a JSON string
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
```

 each 4 bytes are encoded as 5 bef charicters
 ```
 | B0            | B1            | B2            | B3        | Bytes
 | (S0*85^4) + (S1*85^3) + (S2*85^2) + (S3*85^1) + (S4*85^0) | uint32
 | S0         | S1         | S2         | S3         | S4    | String
 ```

* when encoding pad with 0 byte
* when decoding pad with "~" 
then truncate the output to the expected length

lengths
```
| bytes      | 0 | 1 | 2 | 3 | 4 |
| charicters | 0 | 2 | 3 | 4 | 5 |
```

#### regex for base85
```python
b85_regex = """
(?:
    (?:       [!#%&(*+\-.0-[^-z] [!#%&(*+\-.0-[^-|~]{4})
  | (?: {     [!#%&(*+\-.0-=]    [!#%&(*+\-.0-[^-|~]{3})
  | (?: {>    [!#%&(*+\-.0-^]    [!#%&(*+\-.0-[^-|~]{2})
  | (?: {>_   [!#%&(*+\-.0-2]    [!#%&(*+\-.0-[^-|~])
  | (?: {>_3! )
)+ [!#%&(*+\-.0-[^-|~]{0,4}
| [!#%&(*+\-.0-[^-|~]{1,4}
""".replace("\n","").replace(" ","")

char  = f"[!#%&(*+\-.0-[^-|~]" # match a single char of b85
# len 5 forms          full   filling            free
first_0_chars_full = f"       [!#%&(*+\-.0-[^-z] {char}{{4}}"
first_1_chars_full = f"{{     [!#%&(*+\-.0-=]    {char}{{3}}"
first_2_chars_full = f"{{>    [!#%&(*+\-.0-^]    {char}{{2}}"
first_3_chars_full = f"{{>_   [!#%&(*+\-.0-2]    {char}     "
first_4_chars_full = f"{{>_3  !                             "
five_char_forms = f"""
(?: {first_0_chars_full}
  | {first_1_chars_full}
  | {first_2_chars_full}
  | {first_3_chars_full}
  | {first_4_chars_full})
"""
tail  = f"{char}{{0,4}}" # the tail of a match longer then 5
short = f"{char}{{1,4}}" # len 1-4
b85_regex_parts = f"{five_char_forms}+ {tail} | {short}".replace("\n","").replace(" ","")
assert b85_regex_parts == b85_regex
```

