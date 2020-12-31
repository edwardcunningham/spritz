pub fn encode85(buffer: &[u8]) -> String {
    let mut encoded = String::with_capacity(
        (((buffer.len() as f64) / 4.0) * 5.0).ceil() as usize
    );
    for i in 0..buffer.len() / 4 {
        let integer = (buffer[4 * i + 0] as u32) << 24
            | (buffer[4 * i + 1] as u32) << 16
            | (buffer[4 * i + 2] as u32) << 8
            | (buffer[4 * i + 3] as u32) << 0;
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
            tail_buff[i] = buffer[(buffer.len() - tail_len + i) as usize];
        }
        let integer = (tail_buff[0] as u32) << 24
            | (tail_buff[1] as u32) << 16
            | (tail_buff[2] as u32) << 8
            | (tail_buff[3] as u32) << 0;
        for i in 0u32..=tail_len as u32 {
            encoded.push(int2char(integer / (85_u32.pow(4 - i))));
        }
    }
    return encoded;
}

pub fn decode85(string: &str) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(
        ((string.len() as f64) / 5.0 * 4.0).ceil() as usize
    );
    for i in 0..(string.len() / 5) {
        let integer = char2int(string.as_bytes()[i * 5 + 0]) * 85_u32.pow(4)
            + char2int(string.as_bytes()[i * 5 + 1]) * 85_u32.pow(3)
            + char2int(string.as_bytes()[i * 5 + 2]) * 85_u32.pow(2)
            + char2int(string.as_bytes()[i * 5 + 3]) * 85_u32.pow(1)
            + char2int(string.as_bytes()[i * 5 + 4]) * 85_u32.pow(0);
        decoded.push((integer >> 24 & 0xff) as u8);
        decoded.push((integer >> 16 & 0xff) as u8);
        decoded.push((integer >> 8 & 0xff) as u8);
        decoded.push((integer >> 0 & 0xff) as u8);
    }
    let tail_len = string.len() % 5;
    if tail_len > 0 {
        let mut tail_string = [b'~'; 5];
        for i in 0..tail_len {
            tail_string[i] = string.as_bytes()[string.len() - tail_len + i];
        }
        let integer = char2int(tail_string[0]) * 85_u32.pow(4)
            + char2int(tail_string[1]) * 85_u32.pow(3)
            + char2int(tail_string[2]) * 85_u32.pow(2)
            + char2int(tail_string[3]) * 85_u32.pow(1)
            + char2int(tail_string[4]) * 85_u32.pow(0);
        decoded.push((integer >> 24 & 0xff) as u8);
        if tail_len >= 3 {
            decoded.push((integer >> 16 & 0xff) as u8)
        }
        if tail_len == 4 {
            decoded.push((integer >> 8 & 0xff) as u8)
        }
    }
    return decoded;
}

// the characters in the b85 encoding where piked
// becuse thye are all 1 byte in utf8 jason string encoding
// there are 93 characters we then drop extra chaicters to get to 85
// drop ' '  32 since it is ambigus with tab
// drop '"'  34 since it is a string container
// drop '$'  36 since it is not on all keybords
// drop "'"  39 since it is a string container
// drop ')'  41 since it implies grouping
// drop ','  44 since it is a separator
// drop '/'  47 since it is a separator
// drop '\'  92 since it is a escape character
// drop ']'  93 since it implies grouping
// drop '}' 125 since it implies grouping
static BASE85_ALPHABET: &str = "!#%&(*+-.0123456789:;<=>?@ABC\
    DEFGHIJKLMNOPQRSTUVWXYZ[^_`abcdefghijklmnopqrstuvwxyz{|~";

static BASE85_INDEXS: [u8; 128] = [
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,  0, 99,  1, 99,  2,
     3, 99,  4, 99,  5,  6, 99,  7,  8, 99,  9, 10, 11, 12, 13, 14, 15, 16, 17,
    18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
    37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 99, 99, 53,
    54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72,
    73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 99, 84, 99,
];

fn int2char(i: u32) -> char {
    BASE85_ALPHABET.as_bytes()[(i % 85) as usize] as char
}
fn char2int(c: u8) -> u32 {
    BASE85_INDEXS[(c as usize) & 0x7f] as u32
}
