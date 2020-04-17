mod base85;
mod spritz;

use base85::{encode85, decode85};
use spritz::{test_aead, test_hash, test_output, hash};
use std::collections::HashMap;

fn main() {
  base85::run_tests();

  test_output("ABC",     &decode85("MLLTuyBE.B"));
  test_output("spam",    &decode85("v<pd0vU-[@"));
  test_output("arcfour", &decode85(".b%F~r%Dh;"));

  test_hash("ABC",     &decode85("!n{-gSr&iS"));
  test_hash("spam",    &decode85("`Rs3^;A9U3"));
  test_hash("arcfour", &decode85("{2ESf%~&2j"));

  test_aead("ABC",  &decode85("Rv0(1hs@aK7O^;R-I4^ss^SC6Q-pB*x!M4&kJm:PyQXV"));
  test_aead("spam", &decode85("e%{bhFYJ__;BBc>d~{_eHnBAEU7*-{I<+wZYxIO7@j4d_"));
  test_aead(
    "arcfour",
    &decode85("_<L|Qat+pGNrAs+Xc!R|vi8v%4axmYPr~ac&We.wJ;9iiPjZ+"),
  );

  test_keyid("my_key_id", "mVU!c-nS?_");
  test_keyid("ABC",       "isZ{2O{{&8");
  test_keyid("spam",      "ZT+[pIT.OQ");
  test_keyid("arcfour",   "V.|2:mM`g(");
  println!("Pass");

  // let mut KEYRING: Option<HashMap<String, HashMap<String, Vec<u8>>>> = None;
  let mut map: HashMap<&str, i32> = HashMap::new();
  map.insert("a", 1);
  map.insert("b", 2);
  map.insert("c", 3);
  // KEYRING = Some(HashMap::new());
  println!("{:?}", map);
}

fn keyid(key: &[u8]) -> String { encode85(&hash(&key, 8)) }

fn test_keyid(key: &str, expected_keyid: &str){
  let actual_keyid = keyid(&key.as_bytes());
  // println!("{:?} {:?}", actual_keyid, expected_keyid);
  assert_eq!(actual_keyid, expected_keyid);

}