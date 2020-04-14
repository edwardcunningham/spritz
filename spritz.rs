mod base85;
use base85::{encode85, decode85};

fn main() {
  let (_, cpayload) = squeeze(absorb(
    Spritz::initialize_state(),
    "ABC".as_bytes(),
  ), 8);
  println!("output(ABC) = {:?}", cpayload);
  let mut chash = hash("ABC", 32);
  chash.truncate(8);
  println!("hash(ABC) = {:?})", chash);

  println!("{}", encode85(&vec![255, 255, 255, 255]));

  test_output("ABC", &decode85("MLLTuyBE.B"));
  test_output("spam", &decode85("v<pd0vU-[@"));
  test_output("arcfour", &decode85(".b%F~r%Dh;"));

  test_hash("ABC", &decode85("!n{-gSr&iS"));
  test_hash("spam", &decode85("`Rs3^;A9U3"));
  test_hash("arcfour", &decode85("{2ESf%~&2j"));
  base85::run_tests();

  // test_aead("")
}

fn test_output(input: &str, expected: &[u8]){
  let payload = input.as_bytes();
  let mut state = Spritz::initialize_state();
  state = absorb(state, payload);
  let (_, actual) = squeeze(state, 8);
  assert!(actual == expected);
}

fn test_hash(input: &str, expected: &[u8]){
    let mut actual = hash(&input, 32);
    actual.truncate(8);
    assert!(actual == expected);
}

struct Spritz {
  i: u8, j: u8, k: u8,
  z: u8, a: u8, w: u8,
  s: [u8; 256],
}

impl std::fmt::Debug for Spritz {
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {write!(
    f,
    "i {}\nj {}\nk {}\nz {}\na {}\nw {}\ns {:?}",
    self.i, self.j, self.k,
    self.z, self.a, self.w,
    self.s.to_vec()
  )}
}

impl Spritz {
  fn initialize_state() -> Spritz {
    return Spritz{
      i: 0, j: 0, k: 0,
      z: 0, a: 0, w: 1,
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
}

fn absorb(mut state: Spritz, buff: &[u8]) -> Spritz {
  for byte in buff {state = absorb_byte(state, &byte)}
  return state
}

fn absorb_byte(mut state: Spritz, b: &u8) -> Spritz {
  state = absorb_nibble(state, b & 0xf);
  state = absorb_nibble(state, b >> 4);
  return state
}

fn absorb_nibble(mut state: Spritz, x: u8) -> Spritz {
  if state.a >= 128 {
    state = shuffle(state);
  }
  let a = state.a as usize;
  state = swap(
    state,
    a,
    (128 + x) as usize,
  );
  state.a += 1;

  return state
}

fn absorb_stop(mut state: Spritz) -> Spritz{
  if state.a >= 128 { state = shuffle(state) }
  state.a += 1;
  return state;
}

fn shuffle(mut state: Spritz) -> Spritz{
  state = whip(state); state = crush(state);
  state = whip(state); state = crush(state);
  state = whip(state);
  state.a = 0;
  return state;
}

fn whip(mut state: Spritz) -> Spritz{
  for _ in 0..512 { state = update(state) }
  state.w = modadd(state.w, 2);
  return state;
}

fn crush(mut state: Spritz) -> Spritz{
  for v in 0..128{
    if state.s[v] > state.s[255 - v]{
      state = swap(state, v, 255 - v)
    }
  }
  return state;
}

fn squeeze(mut state: Spritz, r: u64) -> (Spritz, Vec<u8>){
  if state.a > 0 { state = shuffle(state) }

  let mut p = Vec::with_capacity(r as usize);

  for _ in 0..r {
    state = drip(state);
    let z = state.z;
    p.push(z);
  }
  return (state, p);
}

fn drip(mut state: Spritz) -> Spritz {
  if state.a > 0 { state = shuffle(state) }
  state = update(state);
 return output(state);
}

fn update(mut state: Spritz) -> Spritz {
  // i = i + w
  // j = k + S[j+S[i]]
  // k = i + k + S[j]
  // S[i], S[j] = S[j], S[i]
  state.i = modadd(state.i, state.w);
  state.j = modadd(state.k, state.s[modadd(
    state.j,
    state.s[state.i as usize]
  ) as usize]);
  state.k = modadd(modadd(state.i, state.k), state.s[state.j as usize]);

  let i = state.i as usize;
  let j = state.j as usize;
  state = swap(state, i, j);
  return state;
}

fn output(mut state: Spritz) -> Spritz {
  // z = S[j + S[i + S[z + k]]]
  state.z = state.s[
    modadd(state.j, state.s[
      modadd(state.i, state.s[
        modadd(state.z, state.k) as usize
      ]) as usize
    ]) as usize
  ];
  return state;
}

fn modadd(a: u8, b: u8) -> u8 { a.wrapping_add(b) }

fn swap(mut state: Spritz, i: usize, j: usize) -> Spritz {
  let t = state.s[i];
  state.s[i] = state.s[j];
  state.s[j] = t;
  return state;
}

fn hash(m: &str, r: u8) -> Vec<u8>{
  let payload = m.as_bytes();
  let mut state = Spritz::initialize_state();
  state = absorb(state, payload);
  state = absorb_stop(state);
  state = absorb(state, &vec![r]);
  let (_state, cpayload) = squeeze(state, r as u64);
  return cpayload;
}
