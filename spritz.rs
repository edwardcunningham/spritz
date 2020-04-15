mod base85;
use base85::decode85;

fn main() {
  let mut spritz = Spritz::init();
  spritz.absorb("ABC".as_bytes());
  let cpayload = spritz.squeeze(8);
  println!("output(ABC) = {:?}", cpayload);
  let mut chash = hash("ABC", 32);
  chash.truncate(8);
  println!("hash(ABC) = {:?})", chash);

  test_output("ABC",     &decode85("MLLTuyBE.B"));
  test_output("spam",    &decode85("v<pd0vU-[@"));
  test_output("arcfour", &decode85(".b%F~r%Dh;"));

  test_hash("ABC",     &decode85("!n{-gSr&iS"));
  test_hash("spam",    &decode85("`Rs3^;A9U3"));
  test_hash("arcfour", &decode85("{2ESf%~&2j"));

  base85::run_tests();

  test_aead("ABC",  &decode85("Rv0(1hs@aK7O^;R-I4^ss^SC6Q-pB*x!M4&kJm:PyQXV"));
  test_aead("spam", &decode85("e%{bhFYJ__;BBc>d~{_eHnBAEU7*-{I<+wZYxIO7@j4d_"));
  test_aead(
    "arcfour",
    &decode85("_<L|Qat+pGNrAs+Xc!R|vi8v%4axmYPr~ac&We.wJ;9iiPjZ+"),
  );
}

fn test_output(input: &str, expected: &[u8]){
  let payload = input.as_bytes();
  let mut spritz = Spritz::init();
  spritz.absorb(payload);
  let actual = spritz.squeeze(8);
  assert!(actual == expected);
}

fn test_hash(input: &str, expected: &[u8]){
    let mut actual = hash(&input, 32);
    actual.truncate(8);
    assert!(actual == expected);
}

fn test_aead(decrypted: &str, encrypted: &[u8]){
  let actual_encrypted = aead(
    "key".as_bytes(),
    "nonce".as_bytes(),
    "header".as_bytes(),
    &decrypted.as_bytes(),
    32
  );
  // println!("{:?}\n{:?}", actual_encrypted, encrypted);
  assert!(actual_encrypted == encrypted);

  let actual_decrypted = aead_decrypt(
    "key".as_bytes(),
    "nonce".as_bytes(),
    "header".as_bytes(),
    &encrypted,
    32
  );

  // println!("{:?}\n{:?}", actual_decrypted, decrypted);
  assert!(actual_decrypted.unwrap() == decrypted);
}

struct Spritz {i: u8, j: u8, k: u8, z: u8, a: u8, w: u8, s: [u8; 256]}

impl std::fmt::Debug for Spritz {
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {write!(
    f, "i {}\nj {}\nk {}\nz {}\na {}\nw {}\ns {:?}",
    self.i, self.j, self.k, self.z, self.a, self.w, self.s.to_vec(),
  )}
}

impl Spritz {
  fn init() -> Spritz {
    return Spritz{
      i: 0, j: 0, k: 0, z: 0, a: 0, w: 1,
      s: [
          0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
         15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,
         30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,
         45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,
         60,  61,  62,  63,  64,  65,  66,  67,  68,  69,  70,  71,  72,  73,  74,
         75,  76,  77,  78,  79,  80,  81,  82,  83,  84,  85,  86,  87,  88,  89,
         90,  91,  92,  93,  94,  95,  96,  97,  98,  99, 100, 101, 102, 103, 104,
        105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
        120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
        135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
        150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164,
        165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
        180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
        195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
        210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224,
        225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
        240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
        255,
      ]
    };
  }

  fn absorb(&mut self, buff: &[u8]){for byte in buff {self.absorb_byte(&byte)}}

  fn absorb_byte(&mut self, b: &u8){
    self.absorb_nibble(b & 0xf);
    self.absorb_nibble(b >> 4);
  }

  fn absorb_nibble(&mut self, x: u8){
    if self.a >= 128 { self.shuffle() }
    let a = self.a as usize;
    self.swap(a, (128 + x) as usize);
    self.a += 1;
  }

  fn absorb_stop(&mut self){
    if self.a >= 128 { self.shuffle() }
    self.a += 1;
  }

  fn shuffle(&mut self){
    self.whip(); self.crush();
    self.whip(); self.crush();
    self.whip();
    self.a = 0;
  }

  fn whip(&mut self){
    for _ in 0..512 { self.update() }
    self.w = modadd(self.w, 2);
  }

  fn crush(&mut self){
    for v in 0..128 { if self.s[v] > self.s[255 - v]{ self.swap(v, 255 - v) } }
  }

  fn squeeze(&mut self, r: u64) -> Vec<u8> {
    if self.a > 0 { self.shuffle() }
    let mut p = Vec::with_capacity(r as usize);
    for _ in 0..r { p.push(self.drip()) }
    return p;
  }

  fn drip(&mut self) -> u8 {
    if self.a > 0 { self.shuffle() }
    self.update();
    return self.output()
  }

  fn update(&mut self){
    // i = i + w
    // j = k + S[j+S[i]]
    // k = i + k + S[j]
    // S[i], S[j] = S[j], S[i]
    self.i = modadd(self.i, self.w);
    self.j = modadd(self.k, self.s[modadd(
      self.j,
      self.s[self.i as usize]
    ) as usize]);
    self.k = modadd(modadd(self.i, self.k), self.s[self.j as usize]);

    let i = self.i as usize;
    let j = self.j as usize;
    self.swap(i, j);
  }

  fn output(&mut self) -> u8 {
    // z = S[j + S[i + S[z + k]]]
    self.z = self.s[
      modadd(self.j, self.s[
        modadd(self.i, self.s[
          modadd(self.z, self.k) as usize
        ]) as usize
      ]) as usize
    ];
    return self.z
  }

  fn swap(&mut self, i: usize, j: usize){
    let t = self.s[i];
    self.s[i] = self.s[j];
    self.s[j] = t;
  }
}

fn modadd(a: u8, b: u8) -> u8 { a.wrapping_add(b) }

fn hash(m: &str, r: u8) -> Vec<u8>{
  let payload = m.as_bytes();
  let mut spritz = Spritz::init();
  spritz.absorb(payload);
  spritz.absorb_stop();
  spritz.absorb(&vec![r]);
  let cpayload = spritz.squeeze(r as u64);
  return cpayload;
}

fn aead(
  key: &[u8],
  nonce: &[u8],
  header : &[u8],
  message : &[u8],
  authentication_tag_length: u8
) -> Vec<u8> {
  let mut spritz = Spritz::init();
  spritz.absorb(key); spritz.absorb_stop();
  spritz.absorb(nonce); spritz.absorb_stop();
  spritz.absorb(header); spritz.absorb_stop();
  let mut cpayload: Vec<u8>= Vec::with_capacity(
    message.len() + authentication_tag_length as usize
  );
  for i in (0..message.len()).step_by(64) {
    let mut chunk = Vec::with_capacity(64);
    for j in 0..64 {
      if i * 64 + j >= message.len() {
        break;
      }
      chunk.push(modadd(spritz.drip(), message[i * 64 + j]));
      cpayload.push(chunk[j]);
    }
    spritz.absorb(&chunk);
    chunk.clear();
  }
  spritz.absorb_stop();
  spritz.absorb_byte(&authentication_tag_length);
  for b in spritz.squeeze(authentication_tag_length as u64) {
    cpayload.push(b);
  }
  return cpayload;
}

fn aead_decrypt(
  key: &[u8],
  nonce: &[u8],
  header : &[u8],
  message : &[u8],
  authentication_tag_length: u8
) -> Result<String, &'static str> {
  let mut payload = "".to_string();
  let mut spritz = Spritz::init();
  spritz.absorb(key); spritz.absorb_stop();
  spritz.absorb(nonce); spritz.absorb_stop();
  spritz.absorb(header); spritz.absorb_stop();
  for i in (0..(message.len() - authentication_tag_length as usize)).step_by(64) {
    let mut chunk = Vec::with_capacity(64);
    for j in 0..64 {
      if i * 64 + j >= (message.len() - authentication_tag_length as usize) {
        break;
      }
      chunk.push(message[i * 64 + j]);
      payload.push(message[i * 64 + j].wrapping_sub(spritz.drip()) as char);
    }
    spritz.absorb(&chunk);
    chunk.clear();
  }
  spritz.absorb_stop();
  spritz.absorb_byte(&authentication_tag_length);
  if spritz.squeeze(authentication_tag_length as u64) !=
     &message[(message.len()-authentication_tag_length as usize)..]{
      return Err("Bad MAC");
  };
  return Ok(payload);
}
