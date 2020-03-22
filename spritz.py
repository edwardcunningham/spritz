class Spritz:

    def __init__(self):
        self.initialise_state()

    def encrypt(self, K, M):
        self.initialise_state()
        self.absorb(K)
        return bytearray(self.add(b1, b2) for b1, b2 in zip(M, self.squeeze(len(M))))

    def decrypt(self, K, C):
        self.initialise_state()
        self.absorb(K)
        return bytearray(self.add(b1, -b2) for b1, b2 in zip(C, self.squeeze(len(C))))

    def hash(self, M, r):
        self.initialise_state()
        self.absorb(M)
        self.absorb_stop()
        self.absorb(bytearray(self.base_10_to_256(r)))
        return self.squeeze(r)

    def swap(self, i1, i2):
        self.S[i1], self.S[i2] = self.S[i2], self.S[i1]

    def initialise_state(self):
        self.i = self.j = self.k = self.z = self.a = 0
        self.w = 1
        self.S = bytearray(range(256))

    def absorb(self, I):
        for b in I:
            self.absorb_byte(b)

    def absorb_byte(self, b):
        self.absorb_nibble(b & 0xf)
        self.absorb_nibble(b >> 4)

    def absorb_nibble(self, x):
        if self.a == 128:
            self.shuffle()
        self.swap(self.a, self.add(128, x))
        self.a = self.add(self.a, 1)

    def absorb_stop(self):
        if self.a  == 128:
            self.shuffle()
        self.a = self.add(self.a, 1)

    def shuffle(self):
        self.whip(512)
        self.crush()
        self.whip(512)
        self.crush()
        self.whip(512)
        self.a = 0

    def whip(self, r):
        for _ in range(r):
            self.update()
        self.w = self.add(self.w, 2)

    def crush(self):
        for v in range(128):
            if self.S[v] > self.S[255 - v]:
                self.swap(v, 255 - v)

    def squeeze(self, r):
        if self.a > 0:
            self.shuffle()
        return bytearray([self.drip() for _ in range(r)])

    def drip(self):
        if self.a > 0:
            self.shuffle()
        self.update()
        return self.output()

    def update(self):
        self.i = self.add(self.i, self.w)
        self.j = self.add(self.k, self.S[self.add(self.j, self.S[self.i])])
        self.k = self.add(self.i, self.k, self.S[self.j])
        self.swap(self.i, self.j)

    def output(self):
        self.z = self.S[self.add(self.j, self.S[self.add(self.i, self.S[self.add(self.z, self.k)])])]
        return self.z

    def aead(self, K, Z, H , M , r):
        """
        Authenticated Encryption with Associated Data

        The procedure AEAD(K, Z, H , M , r ) takes as input
        a key K, a nonce Z (a value that will never be used
        again), a "header" H (this is the "associated data"
        that needs to be authenticated but not encrypted),
        and a message M (to be both encrypted and authenticated),
        and returns a two-part result consisting of
        the encryption of message M followed by an r-byte
        authentication tag (computed over K, Z, H, and M).
        The receipient may need to be sent Z and H if she
        doesn't otherwise know these values; we assume she
        knows K and r.
        See Bellare et al. [4] for more discussion of AEAD mode.
        """
        self.initialise_state()
        self.absorb(K); self.absorb_stop()
        self.absorb(Z); self.absorb_stop()
        self.absorb(H); self.absorb_stop()
        for i in range(0,len(M), 64):
            M_i = M[i:i+64]
            C_i = bytearray(self.add(b1, b2) 
                            for b1, b2 in zip(M_i, self.squeeze(len(M_i))))
            yield from C_i
            self.absorb(C_i)
        self.absorb_stop()
        self.absorb(bytearray(self.base_10_to_256(r)))
        yield from self.squeeze(r)

    def aead_decrypt(self, K, Z, H , C , r):
        transmitted_checksum = C[-r:]
        transmitted_ciphertext = C[:-r]
        self.initialise_state()
        self.absorb(K); self.absorb_stop()
        self.absorb(Z); self.absorb_stop()
        self.absorb(H); self.absorb_stop()
        for i in range(0,len(transmitted_ciphertext), 64):
            C_i = transmitted_ciphertext[i:i+64]
            M_i = bytearray(self.add(b1, -b2)
                            for b1, b2 in zip(C_i, self.squeeze(len(C_i))))
            yield from M_i
            self.absorb(C_i)
        self.absorb_stop()
        self.absorb(bytearray(self.base_10_to_256(r)))
        calculated_checksum = self.squeeze(r)
        if calculated_checksum != transmitted_checksum:
            print(transmitted_checksum, calculated_checksum)
            raise ValueError("Bad MAC")

    def add(self, *args):
        return sum(args) % 256

    def base_10_to_256(self, n):
        m = bytearray()
        while n:
            m.append(n % 256)
            n = n // 256
        return reversed(m)
