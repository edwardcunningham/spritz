mod base85;
mod sbox;
mod spritz;

use self::base85::{decode85, encode85};
use self::sbox::{sbox, sbox_with_scope, unsbox, unsbox_with_scope};
use self::spritz::{aead, aead_decrypt};
use std::fs::File;
use std::io;
use std::io::Read;
use std::time::Instant;

fn main() {
    bench_sbox();
    repl();
}

fn repl() {
    println!("{:?}", sbox(b"bla bla bla"));
    let mut input = String::new();
    loop {
        println!(">");
        input.clear();
        let _n = io::stdin().read_line(&mut input);
        if input == "\n" { break }
        println!("{:?}", unsbox(&input.split("\n").next().unwrap()));
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
    let _boxed = sbox_with_scope(&data, "test_scope");
    println!(
        "box    MB/sec {}",
        (data.len() as f64 / 1048576.0) / tic.elapsed().as_secs_f64(),
    );

    tic = Instant::now();
    let _unboxed = unsbox_with_scope(&_boxed, "test_scope");
    println!(
        "unbox  MB/sec {}",
        (data.len() as f64 / 1048576.0) / tic.elapsed().as_secs_f64(),
    );
}
