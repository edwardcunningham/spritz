pub struct Spritz {i: u8, j: u8, k: u8, z: u8, a: u8, w: u8, s: [u8; 256]}

impl std::fmt::Debug for Spritz {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "i {}\nj {}\nk {}\nz {}\na {}\nw {}\ns {:?}",
            self.i,
            self.j,
            self.k,
            self.z,
            self.a,
            self.w,
            self.s.to_vec(),
        )
    }
}

impl Spritz {
    pub fn init() -> Spritz {
      Spritz{ i: 0, j: 0, k: 0, z: 0, a: 0, w: 1, s: [
          0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,
         14,  15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,
         28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,
         42,  43,  44,  45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,
         56,  57,  58,  59,  60,  61,  62,  63,  64,  65,  66,  67,  68,  69,
         70,  71,  72,  73,  74,  75,  76,  77,  78,  79,  80,  81,  82,  83,
         84,  85,  86,  87,  88,  89,  90,  91,  92,  93,  94,  95,  96,  97,
         98,  99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
        112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
        126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139,
        140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153,
        154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167,
        168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181,
        182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195,
        196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
        210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223,
        224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237,
        238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251,
        252, 253, 254, 255,
      ]}
    }

    pub fn absorb(&mut self, buff: &[u8]) {
        for byte in buff {
            self.absorb_byte(&byte)
        }
    }

    fn absorb_byte(&mut self, b: &u8) {
        self.absorb_nibble(b & 0xf);
        self.absorb_nibble(b >> 4);
    }

    fn absorb_nibble(&mut self, x: u8) {
        if self.a >= 128 {
            self.shuffle()
        }

        let t = self.s[self.a as usize];
        self.s[self.a as usize] = self.s[(128 + x) as usize];
        self.s[(128 + x) as usize] = t;

        self.a += 1;
    }

    fn absorb_stop(&mut self) {
        if self.a >= 128 {
            self.shuffle()
        }
        self.a += 1;
    }

    fn shuffle(&mut self) {
        self.whip(); self.crush();
        self.whip(); self.crush();
        self.whip(); self.a = 0;
    }

    fn whip(&mut self) {
        for _ in 0..512 {self.update()}
        self.w = self.w.wrapping_add(2);
    }

    fn crush(&mut self) {
        for v in 0..128 {
            // s[v], s[255 - v] = min(s[v], s[255 - v]), max(s[v], s[255 - v])
            // if self.s[v] > self.s[255 - v]{
            //     let t = self.s[v as usize];
            //     self.s[v as usize] = self.s[(255 - v) as usize];
            //     self.s[(255 - v) as usize] = t;
            // }

            // min without branching
            let mut a = self.s[v];
            let mut b = self.s[255 - v];
            let swap = (0u8).wrapping_sub((a > b) as u8);
            a = b ^ a;
            b = b ^ (a & swap);
            a = b ^ a;
            self.s[v] = a;
            self.s[255 - v] = b;
        }
    }

    pub fn squeeze(&mut self, r: u64) -> Vec<u8> {
        if self.a > 0 {
            self.shuffle()
        }
        let mut p = Vec::with_capacity(r as usize);
        for _ in 0..r {
            p.push(self.drip())
        }
        return p;
    }

    fn drip(&mut self) -> u8 {
        if self.a > 0 {
            self.shuffle()
        }
        self.update();
        return self.output();
    }

    fn update(&mut self) {
        // i = i + w
        self.i = self.i.wrapping_add(self.w);

        // j = k + S[j+S[i]]
        self.j = self.k.wrapping_add(self.s[
          self.j.wrapping_add(self.s[
            self.i as usize
          ]) as usize
        ]);

        // k = i + k + S[j]
        self.k = self.i.wrapping_add(self.k)
          .wrapping_add(self.s[self.j as usize]);

        // S[i], S[j] = S[j], S[i]
        let a = self.s[self.i as usize];
        let b = self.s[self.j as usize];
        self.s[self.i as usize] = b;
        self.s[self.j as usize] = a;
    }

    fn output(&mut self) -> u8 {
        // z = S[j + S[i + S[z + k]]]
        self.z = self.s[self.j.wrapping_add(
            self.s[self
                .i
                .wrapping_add(self.s[self.z.wrapping_add(self.k) as usize])
                as usize],
        ) as usize];
        return self.z;
    }
}

pub fn hash(m: &[u8], r: u8) -> Vec<u8> {
    let mut spritz = Spritz::init();
    spritz.absorb(m);
    spritz.absorb_stop();
    spritz.absorb_byte(&r);
    return spritz.squeeze(r as u64);
}

pub fn aead(
    key: &[u8],
    nonce: &[u8],
    header: &[u8],
    message: &[u8],
    authentication_tag_length: u8,
) -> Vec<u8> {
    let mut spritz = Spritz::init();
    spritz.absorb(key);
    spritz.absorb_stop();
    spritz.absorb(nonce);
    spritz.absorb_stop();
    spritz.absorb(header);
    spritz.absorb_stop();
    let payload_length = message.len() + authentication_tag_length as usize;
    let mut cpayload: Vec<u8> = Vec::with_capacity(payload_length);
    let mut chunk: Vec<u8> = Vec::with_capacity(64);
    for i in (0..message.len()).step_by(64) {
        for j in 0..64 {
            if i + j >= message.len() {
                break;
            }
            chunk.push(message[i + j].wrapping_add(spritz.drip()));
            cpayload.push(chunk[j]);
        }
        spritz.absorb(&chunk);
        chunk.clear();
    }
    spritz.absorb_stop();
    spritz.absorb_byte(&authentication_tag_length);
    for _ in 0..authentication_tag_length {
        cpayload.push(spritz.drip());
    }
    return cpayload;
}

pub fn aead_decrypt(
    key: &[u8],
    nonce: &[u8],
    header: &[u8],
    message: &[u8],
    authentication_tag_length: u8,
) -> Result<Vec<u8>, &'static str> {
    let mut spritz = Spritz::init();
    spritz.absorb(key);
    spritz.absorb_stop();
    spritz.absorb(nonce);
    spritz.absorb_stop();
    spritz.absorb(header);
    spritz.absorb_stop();
    if message.len() < authentication_tag_length as usize {
        return Err("Bad MAC")
    }
    let payload_length = message.len() - authentication_tag_length as usize;
    let mut payload: Vec<u8> = Vec::with_capacity(payload_length);
    let mut chunk: Vec<u8> = Vec::with_capacity(64);
    for i in (0..payload_length).step_by(64) {
        for j in 0..64 {
            if i + j >= payload_length {
                break;
            }
            chunk.push(message[i + j]);
            payload.push(chunk[j].wrapping_sub(spritz.drip()));
        }
        spritz.absorb(&chunk);
        chunk.clear();
    }
    spritz.absorb_stop();
    spritz.absorb_byte(&authentication_tag_length);
    if spritz.squeeze(authentication_tag_length as u64) !=
       &message[payload_length..] {
        return Err("Bad MAC");
    };
    return Ok(payload);
}
