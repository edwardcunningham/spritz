use std::num::Wrapping;
use std::fmt;

fn main() {
  let (_s, cpayload) = squeeze(absorb(
      initialize_state(), 
      String::from("ABC")
        .into_bytes()
        .into_iter()
        .map(|b| Wrapping(b))
        .collect(),
    ), 8);
//   println!("{:?}", _s);
  println!("output(ABC) = {:?}", cpayload);
  let mut chash = hash("ABC".to_string(), 32);
  chash.truncate(8);
  println!("hash(ABC) = {:?})", chash);

  test_output(b"ABC", vec![119, 154, 142, 1, 249, 233, 203, 192]);
  test_output("spam".to_string(), vec![240, 96, 154, 29, 241, 67, 206, 191]);
  test_output("arcfour".to_string(), vec![26, 250, 139, 94, 227, 55, 219, 199]);

  test_hash("ABC".to_string(), vec![2, 143, 162, 180, 139, 147, 74, 24]);
  test_hash("spam".to_string(), vec![172, 187, 160, 129, 63, 48, 13, 58]);
  test_hash("arcfour".to_string(), vec![255, 140, 242, 104, 9, 76, 135, 185]);
}

fn test_output(input: String, expected: Vec<u8>){
  let payload = String::from(input)
    .into_bytes()
    .into_iter()
    .map(|b: u8| Wrapping(b))
    .collect();
  let mut state = initialize_state();
  state = absorb(state, payload);
  let (_, actual) = squeeze(state, 8);
  assert!(actual == expected);
}

fn test_hash(input: String, expected: Vec<u8>){
    let mut actual = hash(input, 32);
    actual.truncate(8);
    assert!(actual == expected);
}

struct Spritz {
  i: Wrapping<u8>,
  j: Wrapping<u8>,
  k: Wrapping<u8>,
  z: Wrapping<u8>,
  a: Wrapping<u8>,
  w: Wrapping<u8>,
  s: [Wrapping<u8>; 256],
}

impl fmt::Debug for Spritz {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
          f, 
          "i {}\nj {}\nk {}\nz {}\na {}\nw {}\ns {:?}",
          self.i.0,
          self.j.0,
          self.k.0,
          self.z.0,
          self.a.0,
          self.w.0,
          self.s.to_vec()
        )
    }
}

fn initialize_state() -> Spritz {
  let mut state = Spritz{
    i: Wrapping(0), j: Wrapping(0), k: Wrapping(0),
    z: Wrapping(0), a: Wrapping(0), w: Wrapping(1),
    s: [Wrapping(0); 256],
  };
  for v in 0u8..=255 {
    state.s[v as usize] = Wrapping(v);
  }
  return state
}

fn absorb(
    mut state: Spritz,
    buff: Vec<Wrapping<u8>>
  ) -> Spritz {
  for byte in buff {
    state = absorb_byte(state, byte);
  }
  return state
}

fn absorb_byte(mut state: Spritz, b: Wrapping<u8>) -> Spritz {
  state = absorb_nibble(state, Wrapping(b.0 & 0xf));
  state = absorb_nibble(state, Wrapping(b.0 >> 4));
  return state
}

fn absorb_nibble(
    mut state: Spritz, x: Wrapping<u8>
) -> Spritz {
  if state.a >= Wrapping(128u8) {
    state = shuffle(state);
  }
  let a = state.a.0 as usize;
  state = swap(
    state,
    a,
    (Wrapping(128u8) + x).0 as usize,
  );
  state.a = state.a + Wrapping(1u8);

  return state
}

fn absorb_stop(mut state: Spritz) -> Spritz{
  if state.a >= Wrapping(128u8) {
    state = shuffle(state);
  }
  state.a = state.a + Wrapping(1u8);
  return state;
}

fn shuffle(mut state: Spritz) -> Spritz{
  state = whip(state);
  state = crush(state);
  state = whip(state);
  state = crush(state);
  state = whip(state);
  state.a = Wrapping(0u8);
  return state;
}

fn whip(mut state: Spritz) -> Spritz{
  for _ in 0..512 {
    state = update(state);
  }
  state.w = state.w + Wrapping(2u8);
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

fn squeeze(
    mut state: Spritz,
    r: u64
  ) -> (
    Spritz, 
    Vec<u8>, 
  ){
  if state.a.0 > 0 {
    state = shuffle(state);
  }

  let mut p = Vec::with_capacity(r as usize);

  for _ in 0..r {
    state = drip(state);
    let z = state.z.0;
    p.push(z);
  }
  return (state, p);
}

fn drip(mut state: Spritz) -> Spritz {
  if state.a > Wrapping(0) {
    state = shuffle(state);
  }
  state = update(state);
 return output(state);
}

fn update(mut state: Spritz) -> Spritz {
  state.i = state.i + state.w;
  state.j = state.k + state.s[
      (state.j + state.s[state.i.0 as usize]).0 as usize
  ];
  state.k = state.i + state.k + state.s[state.j.0 as usize];
  
  let i = state.i.0 as usize;
  let j = state.j.0 as usize;
  state = swap(state, i, j);
  return state;
}

fn output(mut state: Spritz) -> Spritz {
  state.z = state.s[
    (state.j + state.s[
      (state.i + state.s[
        ((state.z + state.k).0 as usize)
      ]).0 as usize
    ]).0 as usize
  ];
  return state;
}

fn swap(mut state: Spritz, i: usize, j: usize) -> Spritz {
  let t = state.s[i];
  state.s[i] = state.s[j];
  state.s[j] = t;
  return state;
}

fn hash(m: String, r: u8) -> Vec<u8>{
  let payload = m
    .into_bytes()
    .into_iter()
    .map(|b| Wrapping(b))
    .collect();
  let mut state = initialize_state();
  state = absorb(state, payload);
  state = absorb_stop(state);
  state = absorb(state, vec![Wrapping(r)]);
  let (_state, cpayload) = squeeze(state, r as u64);
  return cpayload;
}
