use std::num::Wrapping;
use std::fmt;

mod base85;

fn main() {
  let (_, cpayload) = squeeze(absorb(
      initialize_state(),
      String::from("ABC")
        .into_bytes()
        .into_iter()
        .map(|b| Wrapping(b))
        .collect(),
  ), 8);
  println!("output(ABC) = {:?}", cpayload);
  let mut chash = hash("ABC".to_string(), 32);
  chash.truncate(8);
  println!("hash(ABC) = {:?})", chash);

  test_output("ABC".to_string(), vec![119, 154, 142, 1, 249, 233, 203, 192]);
  test_output("spam".to_string(), vec![240, 96, 154, 29, 241, 67, 206, 191]);
  test_output("arcfour".to_string(), vec![26, 250, 139, 94, 227, 55, 219, 199]);

  test_hash("ABC".to_string(), vec![2, 143, 162, 180, 139, 147, 74, 24]);
  test_hash("spam".to_string(), vec![172, 187, 160, 129, 63, 48, 13, 58]);
  test_hash("arcfour".to_string(), vec![255, 140, 242, 104, 9, 76, 135, 185]);

  base85::run_tests();
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
  let state = Spritz{
    i: Wrapping(0), j: Wrapping(0), k: Wrapping(0),
    z: Wrapping(0), a: Wrapping(0), w: Wrapping(1),
    s: [
        Wrapping(  0u8), Wrapping(  1u8), Wrapping(  2u8), Wrapping(  3u8),
        Wrapping(  4u8), Wrapping(  5u8), Wrapping(  6u8), Wrapping(  7u8),
        Wrapping(  8u8), Wrapping(  9u8), Wrapping( 10u8), Wrapping( 11u8),
        Wrapping( 12u8), Wrapping( 13u8), Wrapping( 14u8), Wrapping( 15u8),
        Wrapping( 16u8), Wrapping( 17u8), Wrapping( 18u8), Wrapping( 19u8),
        Wrapping( 20u8), Wrapping( 21u8), Wrapping( 22u8), Wrapping( 23u8),
        Wrapping( 24u8), Wrapping( 25u8), Wrapping( 26u8), Wrapping( 27u8),
        Wrapping( 28u8), Wrapping( 29u8), Wrapping( 30u8), Wrapping( 31u8),
        Wrapping( 32u8), Wrapping( 33u8), Wrapping( 34u8), Wrapping( 35u8),
        Wrapping( 36u8), Wrapping( 37u8), Wrapping( 38u8), Wrapping( 39u8),
        Wrapping( 40u8), Wrapping( 41u8), Wrapping( 42u8), Wrapping( 43u8),
        Wrapping( 44u8), Wrapping( 45u8), Wrapping( 46u8), Wrapping( 47u8),
        Wrapping( 48u8), Wrapping( 49u8), Wrapping( 50u8), Wrapping( 51u8),
        Wrapping( 52u8), Wrapping( 53u8), Wrapping( 54u8), Wrapping( 55u8),
        Wrapping( 56u8), Wrapping( 57u8), Wrapping( 58u8), Wrapping( 59u8),
        Wrapping( 60u8), Wrapping( 61u8), Wrapping( 62u8), Wrapping( 63u8),
        Wrapping( 64u8), Wrapping( 65u8), Wrapping( 66u8), Wrapping( 67u8),
        Wrapping( 68u8), Wrapping( 69u8), Wrapping( 70u8), Wrapping( 71u8),
        Wrapping( 72u8), Wrapping( 73u8), Wrapping( 74u8), Wrapping( 75u8),
        Wrapping( 76u8), Wrapping( 77u8), Wrapping( 78u8), Wrapping( 79u8),
        Wrapping( 80u8), Wrapping( 81u8), Wrapping( 82u8), Wrapping( 83u8),
        Wrapping( 84u8), Wrapping( 85u8), Wrapping( 86u8), Wrapping( 87u8),
        Wrapping( 88u8), Wrapping( 89u8), Wrapping( 90u8), Wrapping( 91u8),
        Wrapping( 92u8), Wrapping( 93u8), Wrapping( 94u8), Wrapping( 95u8),
        Wrapping( 96u8), Wrapping( 97u8), Wrapping( 98u8), Wrapping( 99u8),
        Wrapping(100u8), Wrapping(101u8), Wrapping(102u8), Wrapping(103u8),
        Wrapping(104u8), Wrapping(105u8), Wrapping(106u8), Wrapping(107u8),
        Wrapping(108u8), Wrapping(109u8), Wrapping(110u8), Wrapping(111u8),
        Wrapping(112u8), Wrapping(113u8), Wrapping(114u8), Wrapping(115u8),
        Wrapping(116u8), Wrapping(117u8), Wrapping(118u8), Wrapping(119u8),
        Wrapping(120u8), Wrapping(121u8), Wrapping(122u8), Wrapping(123u8),
        Wrapping(124u8), Wrapping(125u8), Wrapping(126u8), Wrapping(127u8),
        Wrapping(128u8), Wrapping(129u8), Wrapping(130u8), Wrapping(131u8),
        Wrapping(132u8), Wrapping(133u8), Wrapping(134u8), Wrapping(135u8),
        Wrapping(136u8), Wrapping(137u8), Wrapping(138u8), Wrapping(139u8),
        Wrapping(140u8), Wrapping(141u8), Wrapping(142u8), Wrapping(143u8),
        Wrapping(144u8), Wrapping(145u8), Wrapping(146u8), Wrapping(147u8),
        Wrapping(148u8), Wrapping(149u8), Wrapping(150u8), Wrapping(151u8),
        Wrapping(152u8), Wrapping(153u8), Wrapping(154u8), Wrapping(155u8),
        Wrapping(156u8), Wrapping(157u8), Wrapping(158u8), Wrapping(159u8),
        Wrapping(160u8), Wrapping(161u8), Wrapping(162u8), Wrapping(163u8),
        Wrapping(164u8), Wrapping(165u8), Wrapping(166u8), Wrapping(167u8),
        Wrapping(168u8), Wrapping(169u8), Wrapping(170u8), Wrapping(171u8),
        Wrapping(172u8), Wrapping(173u8), Wrapping(174u8), Wrapping(175u8),
        Wrapping(176u8), Wrapping(177u8), Wrapping(178u8), Wrapping(179u8),
        Wrapping(180u8), Wrapping(181u8), Wrapping(182u8), Wrapping(183u8),
        Wrapping(184u8), Wrapping(185u8), Wrapping(186u8), Wrapping(187u8),
        Wrapping(188u8), Wrapping(189u8), Wrapping(190u8), Wrapping(191u8),
        Wrapping(192u8), Wrapping(193u8), Wrapping(194u8), Wrapping(195u8),
        Wrapping(196u8), Wrapping(197u8), Wrapping(198u8), Wrapping(199u8),
        Wrapping(200u8), Wrapping(201u8), Wrapping(202u8), Wrapping(203u8),
        Wrapping(204u8), Wrapping(205u8), Wrapping(206u8), Wrapping(207u8),
        Wrapping(208u8), Wrapping(209u8), Wrapping(210u8), Wrapping(211u8),
        Wrapping(212u8), Wrapping(213u8), Wrapping(214u8), Wrapping(215u8),
        Wrapping(216u8), Wrapping(217u8), Wrapping(218u8), Wrapping(219u8),
        Wrapping(220u8), Wrapping(221u8), Wrapping(222u8), Wrapping(223u8),
        Wrapping(224u8), Wrapping(225u8), Wrapping(226u8), Wrapping(227u8),
        Wrapping(228u8), Wrapping(229u8), Wrapping(230u8), Wrapping(231u8),
        Wrapping(232u8), Wrapping(233u8), Wrapping(234u8), Wrapping(235u8),
        Wrapping(236u8), Wrapping(237u8), Wrapping(238u8), Wrapping(239u8),
        Wrapping(240u8), Wrapping(241u8), Wrapping(242u8), Wrapping(243u8),
        Wrapping(244u8), Wrapping(245u8), Wrapping(246u8), Wrapping(247u8),
        Wrapping(248u8), Wrapping(249u8), Wrapping(250u8), Wrapping(251u8),
        Wrapping(252u8), Wrapping(253u8), Wrapping(254u8), Wrapping(255u8),
    ]
  };
//   s: [Wrapping(0); 256],
//   for v in 0u8..=255 {
//     state.s[v as usize] = Wrapping(v);
//   }
  return state;
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

fn absorb_nibble(mut state: Spritz, x: Wrapping<u8>) -> Spritz {
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
