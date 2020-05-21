extern crate json;

use crate::base85::{decode85, encode85};
use crate::spritz::{aead, aead_decrypt, hash};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use json::{stringify, JsonValue, JsonResult,  parse};

// static mut keyring: Option<Box<HashMap<String, HashMap<String, Vec<u8>>>>> = None;

pub fn keyid(key: &[u8]) -> String {
    encode85(&hash(&key, 8))
}

pub fn sbox(data: &[u8]) -> String {
    sbox_with_header(data, b"")
}

pub fn sbox_with_header(data: &[u8], header: &[u8]) -> String {
    sbox_with_header_and_scope(data, header, &username())
}

pub fn sbox_with_scope(data: &[u8], scope: &str) -> String {
    sbox_with_header_and_scope(data, b"", scope)
}

pub fn sbox_with_header_and_scope(
    data: &[u8],
    header: &[u8],
    scope: &str,
) -> String {
    sbox_with_header_scope_and_nonce(data, header, scope, &gen_nonce())
}

pub fn sbox_with_header_scope_and_nonce(
    data: &[u8],
    header: &[u8],
    scope: &str,
    nonce: &[u8],
) -> String {
    let mut keyring: HashMap<String, HashMap<String, Vec<u8>>> = HashMap::new();
    let keys_str = read_scope(scope).unwrap();
    let current_key = add_scope(&mut keyring, &keys_str, scope);

    let ciphertext = aead(&current_key, &nonce, &header, data, 32);

    // keyid/nonce/header/cipherbody all in base85
    vec![
        keyid(&current_key),
        encode85(&nonce),
        encode85(&header),
        encode85(&ciphertext),
    ]
    .join("/")
}

pub fn unsbox(msg: &str) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    unsbox_with_scope(msg, &username())
}

fn username() -> String {
    std::env::vars().find(|k| k.0=="LOGNAME").expect("no username").1
}

// fn unwrap_or_err(o: Option<T>, s: &str) -> Result<T, &'static str> {
//     match o {
//         Some(value) => value,
//         None => return Err(s),
//     };
// }

pub fn unsbox_with_scope(msg: &str, scope: &str) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let mut keyring: HashMap<String, HashMap<String, Vec<u8>>> = HashMap::new();
    let keys_str = read_scope(&scope)?;
    add_scope(&mut keyring, &keys_str, scope);

    let mut parts = msg.split('/');
    let keyid =  match parts.next(){
        Some(id) => id,
        // this can not happen "".split('/') is [""]
        None => return Err("no key"), 
    };
    let nonce85 = match parts.next() {
        Some(part) => part,
        None => return Err("no nonce"),
    };
    let header85 = match parts.next() {
        Some(part) => part,
        None => return Err("no header"),
    };
    let body85 = match parts.next() {
        Some(part) => part,
        None => return Err("no body"),
    };

    let scope = match keyring.get(scope) {
        Some(scope_keys) => scope_keys,
        None => return Err("scope not in keyring"),
    };

    let key = match scope.get(keyid){
        Some(key) => key,
        None => return Err("key not in scope"),
    };

    let nonce = decode85(&nonce85);
    let header = decode85(&header85);
    let body = decode85(&body85);

    let msg_data = aead_decrypt(&key, &nonce, &header, &body, 32)?;
    return Ok((header, msg_data));
}

fn read_scope(scope_name: &str) -> Result<String, &'static str> {
    let mut filename = std::path::PathBuf::from(
        std::env::vars().find(|k| k.0=="HOME").expect("home_dir not found").1
    );
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
    let mut data = [0u8; 12];
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut data)
        .unwrap();
    data
}

pub fn sbox_from_json(body: json::JsonValue) -> String{
    sbox(json::stringify(body).as_bytes())
}

pub fn sbox_from_json_with_header(body: json::JsonValue, header: json::JsonValue) -> String {
    sbox_with_header_and_scope(
        json::stringify(body).as_bytes(),
        json::stringify(header).as_bytes(),
        &username()
    )
}

pub fn sbox_from_json_with_scope(body: json::JsonValue, scope: &str) -> String {
    sbox_with_header_and_scope(
        json::stringify(body).as_bytes(),
        b"", 
        scope,
    )
}

pub fn sbox_from_json_with_header_and_scope(
    body: json::JsonValue,
    header: json::JsonValue,
    scope: &str,
) -> String {
    sbox_with_header_and_scope(
        json::stringify(body).as_bytes(),
        json::stringify(header).as_bytes(),
        scope,
    )
}

pub fn sbox_from_json_with_header_scope_and_nonce(
    body: json::JsonValue,
    header: json::JsonValue,
    scope: &str,
    nonce: &[u8],
) -> String {
    sbox_with_header_scope_and_nonce(
        stringify(body).as_bytes(), 
        stringify(header).as_bytes(), 
        scope, 
        nonce,
    )
}

pub fn unsbox_from_json_with_scope(
    msg: &str, scope: &str
) -> Result<(JsonResult<JsonValue>, JsonResult<JsonValue>), &'static str> {
    let (head, body) = unsbox_with_scope(msg, scope)?;
    Ok((
        match std::str::from_utf8(&head){
            Ok(s) => parse(s),
            Err(_) => return Err("header not utf8"),
        }, 
        match std::str::from_utf8(&body){
            Ok(s) => parse(s),
            Err(_) =>  return Err("body not utf8"),
        },
    ))
}
