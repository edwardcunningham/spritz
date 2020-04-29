pub fn encode85(buffer: &[u8]) -> String {
    let mut encoded = String::with_capacity(
        ((buffer.len() as f64)/4.0*5.0).ceil() as usize
    );
    for i in 0..buffer.len() / 4 {
        let integer = (buffer[4 * i + 0] as u32) << 24
                    | (buffer[4 * i + 1] as u32) << 16
                    | (buffer[4 * i + 2] as u32) <<  8
                    | (buffer[4 * i + 3] as u32) <<  0;
        encoded.push(int2char(integer / 85_u32.pow(4)));
        encoded.push(int2char(integer / 85_u32.pow(3)));
        encoded.push(int2char(integer / 85_u32.pow(2)));
        encoded.push(int2char(integer / 85_u32.pow(1)));
        encoded.push(int2char(integer / 85_u32.pow(0)));
    }
    let tail_len = buffer.len() % 4;
    if tail_len > 0 {
        let mut tail_buff = [0; 4];

        for i in 0..tail_len {
            tail_buff[i] = buffer[(buffer.len()- tail_len + i) as usize];
        }

        let integer = (tail_buff[0] as u32) << 24
                    | (tail_buff[1] as u32) << 16
                    | (tail_buff[2] as u32) <<  8
                    | (tail_buff[3] as u32) <<  0;

        for i in 0u32..=tail_len as u32 {
            encoded.push(int2char(integer / (85_u32.pow(4-i))));
        }
    }
    return encoded;
}

pub fn decode85(string: &str) -> Vec<u8>{
    let mut decoded = Vec::with_capacity(
        ((string.len() as f64)/5.0*4.0).ceil() as usize
    );
    for i in 0..(string.len()/5) {
        let integer =
            char2int(char_at(&string, i * 5 + 0)) * 85_u32.pow(4) +
            char2int(char_at(&string, i * 5 + 1)) * 85_u32.pow(3) +
            char2int(char_at(&string, i * 5 + 2)) * 85_u32.pow(2) +
            char2int(char_at(&string, i * 5 + 3)) * 85_u32.pow(1) +
            char2int(char_at(&string, i * 5 + 4)) * 85_u32.pow(0);
        decoded.push((integer >> 24 & 0xff) as u8);
        decoded.push((integer >> 16 & 0xff) as u8);
        decoded.push((integer >>  8 & 0xff) as u8);
        decoded.push((integer >>  0 & 0xff) as u8);
    }
    let tail_len = string.len() % 5;
    if tail_len > 0 {
        let mut tail_string = ['~'; 5];
        for i in 0..tail_len {
            tail_string[i] = char_at(&string, string.len()- tail_len + i);
        }
        let integer = char2int(tail_string[0]) * 85_u32.pow(4)
                    + char2int(tail_string[1]) * 85_u32.pow(3)
                    + char2int(tail_string[2]) * 85_u32.pow(2)
                    + char2int(tail_string[3]) * 85_u32.pow(1)
                    + char2int(tail_string[4]) * 85_u32.pow(0);
        decoded.push((integer >> 24 & 0xff) as u8);
        if tail_len >= 3 {decoded.push((integer >> 16 & 0xff) as u8)}
        if tail_len == 4 {decoded.push((integer >>  8 & 0xff) as u8)}
    }
    return decoded;
}

static BASE85_ALPHABET: &str = "!#%&(*+-.0123456789:;<=>?@ABC\
    DEFGHIJKLMNOPQRSTUVWXYZ[^_`abcdefghijklmnopqrstuvwxyz{|~";

static BASE85_INDEXS: [u8; 128] = [
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    99,  0, 99,  1, 99,  2,  3, 99,  4, 99,  5,  6, 99,  7,  8, 99,
     9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 99, 99, 53, 54,
    55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
    71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 99, 84, 99];

fn char_at(s: &str, i: usize) -> char {s.as_bytes()[i] as char}
fn int2char(i: u32) -> char {char_at(&BASE85_ALPHABET, (i % 85) as usize)}
fn char2int(c: char) -> u32 {BASE85_INDEXS[(c as usize) & 0x7f] as u32}

fn test(buffer: Vec<u8>, string: &str){
    assert_eq!(string, encode85(&buffer));
    assert_eq!(buffer, decode85(string));
}

pub fn run_tests(){
  test(b"\xff\x00\x00\x00"                .to_vec(), "zzB&!"     );
  test(b"\xff\x00\x00"                    .to_vec(), "zzB&"      );
  test(b"\xff\x00"                        .to_vec(), "zzB"       );
  test(b"\xff"                            .to_vec(), "zz"        );
  test(b"\xff\xff\x00\x00"                .to_vec(), "{>T+!"     );
  test(b"\xff\xff"                        .to_vec(), "{>T"       );
  test(b"\xff\xff\xff\x00"                .to_vec(), "{>_0!"     );
  test(b"\xff\xff\xff"                    .to_vec(), "{>_0"      );
  test(b"\xff\xff\xff\xff"                .to_vec(), "{>_3!"     );
  test(b"\xff\xff\xff\xff\xff\x00\x00\x00".to_vec(), "{>_3!zzB&!");
  test(b"\xff\xff\xff\xff\xff\x00\x00"    .to_vec(), "{>_3!zzB&" );
  test(b"\xff\xff\xff\xff\xff\x00"        .to_vec(), "{>_3!zzB"  );
  test(b"\xff\xff\xff\xff\xff"            .to_vec(), "{>_3!zz"   );
  test(b"\xff\xff\xff\xff\xff\xff"        .to_vec(), "{>_3!{>T"  );
  test(b"\xff\xff\xff\xff\xff\xff\xff"    .to_vec(), "{>_3!{>_0" );
  test(b"\xff\xff\xff\xff\xff\xff\xff\xff".to_vec(), "{>_3!{>_3!");
  test(b"!\xad\x97\x96\\\xb9O\x1bek\xc9\x87\x9d:#\xe5b\xe5\x81d\r\xd7ofW\
      \x8fE\xf5\xde\x9eJ\x89".to_vec(),
      "1o(.{Dm0_RGYeJIYT>#_Fkh5U(M2T7C3%nIpUcDz");
  test(b"Man is distinguished, not only by his reason, but by this singul\
    ar passion from other animals, which is a lust of the mind, that \
    by a perseverance of delight in the continued and indefatigable \
    generation of knowledge, exceeds the short vehemence of any car\
    nal pleasure.".to_vec(),
    "?rywfHtjJ3HtmH7JP101L-n2y56PpQLBMRDIrF4:Mx&l=L!2R=FB<F.56PJKLBM(B\
    1K^@8L!2UBJP104FB0Q6FB<R-Jn3d6Kk;mAJnnb-Kbmm4Ht4?xL#GM`HVI{q1JMuD\
    F9HH5L0*UIGn~85GQaq-JOj@FLJ20.1Ie[CF9HT%Kkan>GZJ9{FyEl&Gn|^yIpcTy\
    LBM@>1K^@41InD3LJ;_>GXtwtJOit-JOlBrFBE9zF@L(i1J;>+GZJ:&HtFt9Jm@23\
    JP{h>GXwLj56PSQFyH:fL!2XBGQb*3JnZyHM(MD~J4XZxGQaw+1IZ5;1Imq%JOOE-\
    K2?.wL08S=5k");
  test(b"\x00\t\x98b\x0f\xc7\x99C\x1f\x85\x9a$/C\x9b\x05?\x01\x9b\xe6N\xbf\
    \x9c\xc7^}\x9d\xa8n;\x9e\x89}\xf9\x9fj\x8d\xb7\xa0K\x9du\xa1,\xad\
    3\xa2\r\xbc\xf1\xa2\xee\xcc\xaf\xa3\xcf\xdcm\xa4\xb0\xec+\xa5\x91\
    \xfb\xe9\xa6r".to_vec(),
    "!#%&(*+-.0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[^_`abcdefghij\
    klmnopqrstuvwxyz{|~");
}
