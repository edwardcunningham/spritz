mod base85;
mod sbox;
mod spritz;

use self::base85::{decode85, encode85};
use self::sbox::{keyid, sbox, sbox_with_headers_scope_and_nonce, unsbox, unsbox_with_scope};
use self::spritz::{aead, aead_decrypt, hash};
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::Read;
use std::time::Instant;

fn main() {
    run_tests();

    test_output(b"ABC", &decode85("MLLTuyBE.B"));
    test_output(b"spam", &decode85("v<pd0vU-[@"));
    test_output(b"arcfour", &decode85(".b%F~r%Dh;"));

    test_hash(b"ABC", &decode85("!n{-gSr&iS"));
    test_hash(b"spam", &decode85("`Rs3^;A9U3"));
    test_hash(b"arcfour", &decode85("{2ESf%~&2j"));

    test_aead(
        b"ABC",
        &decode85("Rv0(1hs@aK7O^;R-I4^ss^SC6Q-pB*x!M4&kJm:PyQXV"),
    );
    test_aead(
        b"spam",
        &decode85("e%{bhFYJ__;BBc>d~{_eHnBAEU7*-{I<+wZYxIO7@j4d_"),
    );
    test_aead(
        b"arcfour",
        &decode85("_<L|Qat+pGNrAs+Xc!R|vi8v%4axmYPr~ac&We.wJ;9iiPjZ+"),
    );

    test_keyid("my_key_id", "mVU!c-nS?_");
    test_keyid("ABC", "isZ{2O{{&8");
    test_keyid("spam", "ZT+[pIT.OQ");
    test_keyid("arcfour", "V.|2:mM`g(");

    test_sbox(
        "%Cl*awJGQB/!!!!!!!!!!!!!!!/NWuTFJnH>99c5b_L0-k7FzNB|2-6/`j3|\
       7XFwj^sll#C.G4>v%EJo!AQz;Vb5mmcIMkgBK&cLB@C>m=.w074[lVu#r?~",
        Ok((
            "{\"scope\":\"test_scope\"}".to_string(),
            b"this is some data!".to_vec(),
        )),
    );
    test_sbox(
        "%Cl*awJGQB/!!!!!!!!!!!!!!!/NWuTFJnH>99c5b_L0-k7FzNB|2-6/agq~\
       IqSSb1h4a.H0_@<{&kjL!rR(ORtq4+uf~*%.qnofsHf7q",
        Ok((
            "{\"scope\":\"test_scope\"}".to_string(),
            b"woo hoo".to_vec(),
        )),
    );
    test_sbox("", Err("key not in scope"));
    test_sbox("%Cl*awJGQB", Err("no nonce"));
    test_sbox("%Cl*awJGQB/!!!!!!!!!!!!!!!", Err("no header"));
    test_sbox(
        "%Cl*awJGQB/!!!!!!!!!!!!!!!/NWuTFJnH>99c5b_L0-k7FzNB|2-6",
        Err("no payload"),
    );

    println!("Pass");
    bench_sbox();
    // repl();
}

fn repl() {
    let mut input = String::new();
    while input != "\n" {
        print!(">");
        input.clear();
        let n = io::stdin().read_line(&mut input);
        println!(
            "{:?}\n{:?}\n{:?}",
            n,
            input,
            unsbox(&input.split("\n").next().unwrap())
        );
    }
}

pub fn bench_sbox() {
    let mut tic = Instant::now();
    let mut data = vec![0u8; 1048576]; // 1048576 is 1MB
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut data)
        .unwrap();
    println!(
        "rand   MB/sec {}\n",
        (data.len() as f64 / 1048576.0) / tic.elapsed().as_secs_f64(),
    );

    tic = Instant::now();
    let _enced = encode85(&data);
    println!(
        "enc85  MB/sec {}",
        (data.len() as f64 / 1048576.0) / tic.elapsed().as_secs_f64(),
    );

    tic = Instant::now();
    let _deced = decode85(&_enced);
    println!(
        "dec85  MB/sec {}\n",
        (data.len() as f64 / 1048576.0) / tic.elapsed().as_secs_f64(),
    );

    tic = Instant::now();
    let ciphertext = aead(b"key", b"nonce", b"header", &data, 32);
    println!(
        "aead   MB/sec {}",
        (data.len() as f64 / 1048576.0) / tic.elapsed().as_secs_f64(),
    );

    tic = Instant::now();
    let _msg_data = aead_decrypt(b"key", b"nonce", b"header", &ciphertext, 32);
    if _msg_data.is_err() {
        println!("{:?}", _msg_data)
    }
    println!(
        "unaead MB/sec {}\n",
        (data.len() as f64 / 1048576.0) / tic.elapsed().as_secs_f64(),
    );

    tic = Instant::now();
    let _boxed = sbox(&data);
    println!(
        "box    MB/sec {}",
        (data.len() as f64 / 1048576.0) / tic.elapsed().as_secs_f64(),
    );

    tic = Instant::now();
    let _unboxed = unsbox(&_boxed);
    println!(
        "unbox  MB/sec {}",
        (data.len() as f64 / 1048576.0) / tic.elapsed().as_secs_f64(),
    );
}

pub fn test_sbox(
  expected_boxed: &str,
  expected_unboxed: Result<(String, Vec<u8>), &'static str>,
) {
    // """test_scope.keyring
    // aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    // """

    let actual_unboxed = unsbox_with_scope(expected_boxed, "test_scope");
    assert_eq!(actual_unboxed, expected_unboxed);

    if expected_unboxed.is_ok() {
        let actual_boxed = sbox_with_headers_scope_and_nonce(
            &expected_unboxed.unwrap().1,
            HashMap::new(),
            "test_scope",
            &[0u8; 12],
        );
        assert_eq!(actual_boxed, expected_boxed);
    }
}

pub fn test_keyid(key: &str, expected_keyid: &str) {
    let actual_keyid = keyid(&key.as_bytes());
    assert_eq!(actual_keyid, expected_keyid);
}

fn test(buffer: Vec<u8>, string: &str) {
    assert_eq!(string, encode85(&buffer));
    assert_eq!(buffer, decode85(string));
}

pub fn run_tests() {
    test(b"\xff\x00\x00\x00".to_vec(), "zzB&!");
    test(b"\xff\x00\x00".to_vec(), "zzB&");
    test(b"\xff\x00".to_vec(), "zzB");
    test(b"\xff".to_vec(), "zz");
    test(b"\xff\xff\x00\x00".to_vec(), "{>T+!");
    test(b"\xff\xff".to_vec(), "{>T");
    test(b"\xff\xff\xff\x00".to_vec(), "{>_0!");
    test(b"\xff\xff\xff".to_vec(), "{>_0");
    test(b"\xff\xff\xff\xff".to_vec(), "{>_3!");
    test(b"\xff\xff\xff\xff\xff\x00\x00\x00".to_vec(), "{>_3!zzB&!");
    test(b"\xff\xff\xff\xff\xff\x00\x00".to_vec(), "{>_3!zzB&");
    test(b"\xff\xff\xff\xff\xff\x00".to_vec(), "{>_3!zzB");
    test(b"\xff\xff\xff\xff\xff".to_vec(), "{>_3!zz");
    test(b"\xff\xff\xff\xff\xff\xff".to_vec(), "{>_3!{>T");
    test(b"\xff\xff\xff\xff\xff\xff\xff".to_vec(), "{>_3!{>_0");
    test(b"\xff\xff\xff\xff\xff\xff\xff\xff".to_vec(), "{>_3!{>_3!");
    test(
        b"!\xad\x97\x96\\\xb9O\x1bek\xc9\x87\x9d:#\xe5b\xe5\x81d\r\xd7ofW\
      \x8fE\xf5\xde\x9eJ\x89"
            .to_vec(),
        "1o(.{Dm0_RGYeJIYT>#_Fkh5U(M2T7C3%nIpUcDz",
    );
    test(
        b"Man is distinguished, not only by his reason, but by this singul\
    ar passion from other animals, which is a lust of the mind, that \
    by a perseverance of delight in the continued and indefatigable \
    generation of knowledge, exceeds the short vehemence of any car\
    nal pleasure."
            .to_vec(),
        "?rywfHtjJ3HtmH7JP101L-n2y56PpQLBMRDIrF4:Mx&l=L!2R=FB<F.56PJKLBM(B\
    1K^@8L!2UBJP104FB0Q6FB<R-Jn3d6Kk;mAJnnb-Kbmm4Ht4?xL#GM`HVI{q1JMuD\
    F9HH5L0*UIGn~85GQaq-JOj@FLJ20.1Ie[CF9HT%Kkan>GZJ9{FyEl&Gn|^yIpcTy\
    LBM@>1K^@41InD3LJ;_>GXtwtJOit-JOlBrFBE9zF@L(i1J;>+GZJ:&HtFt9Jm@23\
    JP{h>GXwLj56PSQFyH:fL!2XBGQb*3JnZyHM(MD~J4XZxGQaw+1IZ5;1Imq%JOOE-\
    K2?.wL08S=5k",
    );
    test(
        b"\x00\t\x98b\x0f\xc7\x99C\x1f\x85\x9a$/C\x9b\x05?\x01\x9b\xe6N\xbf\
    \x9c\xc7^}\x9d\xa8n;\x9e\x89}\xf9\x9fj\x8d\xb7\xa0K\x9du\xa1,\xad\
    3\xa2\r\xbc\xf1\xa2\xee\xcc\xaf\xa3\xcf\xdcm\xa4\xb0\xec+\xa5\x91\
    \xfb\xe9\xa6r"
            .to_vec(),
        "!#%&(*+-.0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[^_`abcdefghij\
    klmnopqrstuvwxyz{|~",
    );
}

pub fn test_output(input: &[u8], expected: &[u8]) {
    let payload = input;
    let mut spritz = spritz::Spritz::init();
    spritz.absorb(payload);
    let actual = spritz.squeeze(8);
    assert!(actual == expected);
}

pub fn test_hash(input: &[u8], expected: &[u8]) {
    let mut actual = hash(&input, 32);
    actual.truncate(8);
    assert!(actual == expected);
}

pub fn test_aead(decrypted: &[u8], encrypted: &[u8]) {
    let actual_encrypted = aead(b"key", b"nonce", b"header", &decrypted, 32);
    assert!(actual_encrypted == encrypted);

    let actual_decrypted = aead_decrypt(
        "key".as_bytes(),
        "nonce".as_bytes(),
        "header".as_bytes(),
        &encrypted,
        32,
    );
    assert!(actual_decrypted.unwrap() == decrypted);
}
