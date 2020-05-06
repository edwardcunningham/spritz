extern crate dirs;
extern crate json;
extern crate users;

use crate::base85::{decode85, encode85};
use crate::spritz::{aead, aead_decrypt, hash};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

pub fn keyid(key: &[u8]) -> String {
    encode85(&hash(&key, 8))
}

pub fn sbox(data: &[u8]) -> String {
    sbox_with_headers(data, HashMap::new())
}

pub fn sbox_with_headers(data: &[u8], headers: HashMap<String, String>) -> String {
    sbox_with_headers_and_scope(data, headers, &username())
}

pub fn sbox_with_scope(data: &[u8], scope: &str) -> String {
    sbox_with_headers_and_scope(data, HashMap::new(), scope)
}

pub fn sbox_with_headers_and_scope(
    data: &[u8],
    headers: HashMap<String, String>,
    scope: &str,
) -> String {
    sbox_with_headers_scope_and_nonce(data, headers, scope, &gen_nonce())
}

pub fn sbox_with_headers_scope_and_nonce(
    data: &[u8],
    mut headers: HashMap<String, String>,
    scope: &str,
    nonce: &[u8],
) -> String {
    let mut keyring: HashMap<String, HashMap<String, Vec<u8>>> = HashMap::new();
    let keys_str = read_scope(scope).unwrap();
    let current_key = add_scope(&mut keyring, &keys_str, scope);

    headers.insert("scope".to_string(), scope.to_string());
    let header = json::stringify(headers);
    let ciphertext = aead(&current_key, &nonce, &header.as_bytes(), data, 32);

    // keyid/nonce/header/ciphertext all in base85
    vec![
        keyid(&current_key),
        encode85(&nonce),
        encode85(header.as_bytes()),
        encode85(&ciphertext),
    ]
    .join("/")
}

pub fn unsbox(msg: &str) -> Result<(String, Vec<u8>), &'static str> {
    unsbox_with_scope(msg, &username())
}

fn username() -> String {
    users::get_current_username()
        .expect("no username")
        .into_string()
        .expect("username not utf-8")
}

pub fn unsbox_with_scope(msg: &str, scope: &str) -> Result<(String, Vec<u8>), &'static str> {
    let mut keyring: HashMap<String, HashMap<String, Vec<u8>>> = HashMap::new();
    let keys_str = read_scope(&scope)?;
    add_scope(&mut keyring, &keys_str, scope);

    let mut parts = msg.split('/');
    let key = match keyring.get(scope) {
        Some(scope_keys) => match scope_keys.get(parts.next().expect("no key")) {
            Some(key) => key,
            None => return Err("key not in scope"),
        },
        None => return Err("scope not in keyring"),
    };
    let nonce = decode85(&match parts.next() {
        Some(part) => part,
        None => return Err("no nonce"),
    });
    let header = decode85(&match parts.next() {
        Some(part) => part,
        None => return Err("no header"),
    });
    let ciphertext = decode85(&match parts.next() {
        Some(part) => part,
        None => return Err("no payload"),
    });
    let msg_data = aead_decrypt(&key, &nonce, &header, &ciphertext, 32)?;
    return Ok((String::from_utf8(header).unwrap(), msg_data));
}

fn read_scope(scope_name: &str) -> Result<String, &'static str> {
    let mut filename = dirs::home_dir().expect("home_dir not found");
    filename.push(".sbox");
    filename.push(scope_name);
    filename.set_extension("keyring");
    match std::fs::read_to_string(filename) {
        Ok(data) => Ok(data),
        Err(_) => Err("bad keyring file"),
    }
}

fn add_scope(
    // keyring = {scope: {key_id: key}}
    keyring: &mut HashMap<String, HashMap<String, Vec<u8>>>,
    keys_str: &str,
    scope: &str,
) -> Vec<u8> {
    keyring.insert(scope.to_string(), HashMap::new());
    let scope_keys = keyring.get_mut(scope).unwrap();
    let mut lastkey = Vec::new();
    for row in keys_str.split('\n') {
        if !row.is_empty() {
            let key85 = row.split(' ').next().unwrap();
            let key = decode85(key85);
            lastkey = key.clone();
            scope_keys.insert(keyid(&key), key);
        }
    }
    return lastkey;
}

fn gen_nonce() -> [u8; 12] {
    let mut data = [0u8; 12]; // 1048576 is 1MB
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut data)
        .unwrap();
    data
}
