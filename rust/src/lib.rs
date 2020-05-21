mod base85;
mod sbox;
mod spritz;

pub use self::base85::{
    decode85, 
    encode85,
};
pub use self::sbox::{
    keyid,
    sbox,
    sbox_with_header,
    sbox_with_scope,
    sbox_with_header_and_scope,
    sbox_from_json,
    sbox_from_json_with_header,
    sbox_from_json_with_scope,
    sbox_from_json_with_header_and_scope,
    sbox_from_json_with_header_scope_and_nonce,
    unsbox,
    unsbox_with_scope,
    unsbox_from_json_with_scope,
};
pub use self::spritz::{
    hash,
    aead,
    aead_decrypt,
};

#[cfg(test)]
mod tests {
    use crate::base85::{decode85, encode85};
    use crate::sbox::{
        keyid,
        sbox_with_header_scope_and_nonce,
        sbox_from_json_with_header_scope_and_nonce,
        unsbox_with_scope,
        unsbox_from_json_with_scope,
    };
    use crate::spritz::{Spritz, aead, aead_decrypt, hash};
    use json::{JsonValue, Null};

    #[test]
    fn output_tests() {
        test_output(b"ABC", &decode85("MLLTuyBE.B"));
        test_output(b"spam", &decode85("v<pd0vU-[@"));
        test_output(b"arcfour", &decode85(".b%F~r%Dh;"));
    }

    #[test]
    fn hash_tests() {
        test_hash(b"ABC", &decode85("!n{-gSr&iS"));
        test_hash(b"spam", &decode85("`Rs3^;A9U3"));
        test_hash(b"arcfour", &decode85("{2ESf%~&2j"));
    }

    #[test]
    fn aead_tests() {
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
    }

    #[test]
    fn keyid_tests() {
        test_keyid("my_key_id", "mVU!c-nS?_");
        test_keyid("ABC", "isZ{2O{{&8");
        test_keyid("spam", "ZT+[pIT.OQ");
        test_keyid("arcfour", "V.|2:mM`g(");
    }

    #[test]
    fn sbox_tests() {
        test_sbox(
            "%Cl*awJGQB/!!!!!!!!!!!!!!!/NWuTFJnH>99c5b_L0-k7FzNB|2-6/`j3|\
           7XFwj^sll#C.G4>v%EJo!AQz;Vb5mmcIMkgBK&cLB@C>m=.w074[lVu#r?~",
            Ok((
                b"{\"scope\":\"test_scope\"}".to_vec(),
                b"this is some data!".to_vec(),
            )),
        );
        test_sbox(
            "%Cl*awJGQB/!!!!!!!!!!!!!!!/NWuTFJnH>99c5b_L0-k7FzNB|2-6/agq~\
           IqSSb1h4a.H0_@<{&kjL!rR(ORtq4+uf~*%.qnofsHf7q",
            Ok((
                b"{\"scope\":\"test_scope\"}".to_vec(),
                b"woo hoo".to_vec(),
            )),
        );
        test_sbox("", Err("no nonce"));
        test_sbox("/", Err("no header"));
        test_sbox("//", Err("no body"));
        test_sbox("///", Err("key not in scope"));
        test_sbox("%Cl*awJGQB///", Err("Bad MAC"));
        test_sbox(
            "%Cl*awJGQB/!!!!!!!!!!!!!!!//\
            @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
            Err("Bad MAC"),
        );
        test_sbox_from_json_with_header_and_scope(
            Null, 
            Null, 
            &"%Cl*awJGQB/!!!!!!!!!!!!!!!/JQZk9/\
            LbX(2kav[pMqQMC*`7oUS(j&m7j*B{9-x^5V-~h7Bptob");
    }

    fn test_base85(buffer: Vec<u8>, string: &str) {
        assert_eq!(string, encode85(&buffer));
        assert_eq!(buffer, decode85(string));
    }

    pub fn test_output(input: &[u8], expected: &[u8]) {
        let payload = input;
        let mut spritz = Spritz::init();
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
        let actual_encrypted = aead(
            b"key",
            b"nonce",
            b"header",
            &decrypted,
            32,
        );
        assert!(actual_encrypted == encrypted);
    
        let actual_decrypted = aead_decrypt(
            b"key",
            b"nonce",
            b"header",
            &encrypted,
            32,
        );
        assert!(actual_decrypted.unwrap() == decrypted);
    }

    pub fn test_sbox(
        expected_boxed: &str,
        expected_unboxed: Result<(Vec<u8>, Vec<u8>), &'static str>,
      ) {
          // """test_scope.keyring
          // aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          // """
      
          let actual_unboxed = unsbox_with_scope(expected_boxed, "test_scope");
          assert_eq!(actual_unboxed, expected_unboxed);
      
          if expected_unboxed.is_ok() {
              let actual_boxed = sbox_with_header_scope_and_nonce(
                  &expected_unboxed.unwrap().1,
                  b"{\"scope\":\"test_scope\"}",
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

    #[test]
    fn base85_tests() {
        test_base85(b"\xff\x00\x00\x00"                .to_vec(), "zzB&!"     );
        test_base85(b"\xff\x00\x00"                    .to_vec(), "zzB&"      );
        test_base85(b"\xff\x00"                        .to_vec(), "zzB"       );
        test_base85(b"\xff"                            .to_vec(), "zz"        );
        test_base85(b"\xff\xff\x00\x00"                .to_vec(), "{>T+!"     );
        test_base85(b"\xff\xff"                        .to_vec(), "{>T"       );
        test_base85(b"\xff\xff\xff\x00"                .to_vec(), "{>_0!"     );
        test_base85(b"\xff\xff\xff"                    .to_vec(), "{>_0"      );
        test_base85(b"\xff\xff\xff\xff"                .to_vec(), "{>_3!"     );
        test_base85(b"\xff\xff\xff\xff\xff\x00\x00\x00".to_vec(), "{>_3!zzB&!");
        test_base85(b"\xff\xff\xff\xff\xff\x00\x00"    .to_vec(), "{>_3!zzB&" );
        test_base85(b"\xff\xff\xff\xff\xff\x00"        .to_vec(), "{>_3!zzB"  );
        test_base85(b"\xff\xff\xff\xff\xff"            .to_vec(), "{>_3!zz"   );
        test_base85(b"\xff\xff\xff\xff\xff\xff"        .to_vec(), "{>_3!{>T"  );
        test_base85(b"\xff\xff\xff\xff\xff\xff\xff"    .to_vec(), "{>_3!{>_0" );
        test_base85(b"\xff\xff\xff\xff\xff\xff\xff\xff".to_vec(), "{>_3!{>_3!");
        test_base85(
            b"!\xad\x97\x96\\\xb9O\x1bek\xc9\x87\x9d:#\xe5b\xe5\x81d\r\xd7ofW\
          \x8fE\xf5\xde\x9eJ\x89"
                .to_vec(),
            "1o(.{Dm0_RGYeJIYT>#_Fkh5U(M2T7C3%nIpUcDz",
        );
        test_base85(
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
        test_base85(
            b"\x00\t\x98b\x0f\xc7\x99C\x1f\x85\x9a$/C\x9b\x05?\x01\x9b\xe6N\xbf\
        \x9c\xc7^}\x9d\xa8n;\x9e\x89}\xf9\x9fj\x8d\xb7\xa0K\x9du\xa1,\xad\
        3\xa2\r\xbc\xf1\xa2\xee\xcc\xaf\xa3\xcf\xdcm\xa4\xb0\xec+\xa5\x91\
        \xfb\xe9\xa6r"
                .to_vec(),
            "!#%&(*+-.0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[^_`abcdefghij\
        klmnopqrstuvwxyz{|~",
        );
    }

    fn test_sbox_from_json_with_header_and_scope(header: JsonValue, body: JsonValue, expected: &str){
        let actual_sbox = sbox_from_json_with_header_scope_and_nonce(
            body, 
            header, 
            &"test_scope",
            &[0u8; 12],
        );
        let actual_usbox = unsbox_from_json_with_scope(
            expected,
            &"test_scope",
        );
        println!("{:?} {:?}", actual_sbox, actual_usbox);
        assert!(actual_sbox == expected);
    }
}
