#!/usr/bin/env python


IR = (
    1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0,
    1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0,
    0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
    0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1,
    1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1,
    0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0,
    1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1,
    1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1,
    0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
    1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0,
    0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1,
    0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1,
    1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0,
)


def num2bits(num, bitlength):
    bits = []
    for i in range(bitlength):
        bits.append(num & 1)
        num >>= 1
    return bits


def bits2num(bits):
    num = 0
    for i, x in enumerate(bits):
        assert x == 0 or x == 1
        num += (x << i)
    return num


def lfsr(iv):
    state = num2bits(iv, 80)
    for i in range(254 * 2):
        yield state[0]
        state.append(state[0] ^ state[19] ^ state[30] ^ state[67])
        state.pop(0)


class KATAN():
    def __init__(self, master_key=0, version=32):
        assert version in (32, 48, 64)
        self.version = version

        if 32 == self.version:
            self.LEN_L1 = 13
            self.LEN_L2 = 19
            self.X = (None, 12, 7, 8, 5, 3)  # starting from 1
            self.Y = (None, 18, 7, 12, 10, 8, 3)
        elif 48 == self.version:
            self.LEN_L1 = 19
            self.LEN_L2 = 29
            self.X = (None, 18, 12, 15, 7, 6)
            self.Y = (None, 28, 19, 21, 13, 15, 6)
        else:
            self.LEN_L1 = 25
            self.LEN_L2 = 39
            self.X = (None, 24, 15, 20, 11, 9)
            self.Y = (None, 38, 25, 33, 21, 14, 9)

        self.change_key(master_key)

    def change_key(self, master_key):
        self.key = []
        stream = lfsr(master_key)
        for i in range(254 * 2):
            self.key.append(stream.next())

    def one_round_enc(self, round):
        k_a = self.key[2 * round]
        k_b = self.key[2 * round + 1]

        self.f_a = self.L1[self.X[1]] ^ self.L1[self.X[2]]  \
                ^ (self.L1[self.X[3]] & self.L1[self.X[4]]) \
                ^ k_a
        if IR[round]:
            self.f_a ^= self.L1[self.X[5]]

        self.f_b = self.L2[self.Y[1]] ^ self.L2[self.Y[2]]  \
                ^ (self.L2[self.Y[3]] & self.L2[self.Y[4]]) \
                ^ (self.L2[self.Y[5]] & self.L2[self.Y[6]]) \
                ^ k_b

        self.L1.pop()
        self.L1.insert(0, self.f_b)

        self.L2.pop()
        self.L2.insert(0, self.f_a)

    def enc(self, plaintext, from_round=0, to_round=253):
        self.plaintext_bits = num2bits(plaintext, self.version)
        self.L2 = self.plaintext_bits[:self.LEN_L2]
        self.L1 = self.plaintext_bits[self.LEN_L2:]

        for round in range(from_round, to_round + 1):
            self.one_round_enc(round)
            if self.version > 32:
                self.one_round_enc(round)
                if self.version > 48:
                    self.one_round_enc(round)
        return bits2num(self.L2 + self.L1)

    def one_round_dec(self, round):
        k_a = self.key[2 * round]
        k_b = self.key[2 * round + 1]

        self.f_a = self.L2[0] ^ self.L1[self.X[2] + 1]              \
                ^ (self.L1[self.X[3] + 1] & self.L1[self.X[4] + 1]) \
                ^ k_a
        if IR[round]:
            self.f_a ^= self.L1[self.X[5] + 1]

        self.f_b = self.L1[0] ^ self.L2[self.Y[2] + 1]              \
                ^ (self.L2[self.Y[3] + 1] & self.L2[self.Y[4] + 1]) \
                ^ (self.L2[self.Y[5] + 1] & self.L2[self.Y[6] + 1]) \
                ^ k_b

        self.L1.pop(0)
        self.L1.append(self.f_a)

        self.L2.pop(0)
        self.L2.append(self.f_b)

    def dec(self, ciphertext, from_round=253, to_round=0):
        self.ciphertext_bits = num2bits(ciphertext, self.version)
        self.L2 = self.ciphertext_bits[:self.LEN_L2]
        self.L1 = self.ciphertext_bits[self.LEN_L2:]

        for round in range(from_round, to_round - 1, -1):
            self.one_round_dec(round)
            if self.version > 32:
                self.one_round_dec(round)
                if self.version > 48:
                    self.one_round_dec(round)
        return bits2num(self.L2 + self.L1)


if __name__ == '__main__':
    #key = 0xFFFFFFFFFFFFFFFFFFFF
    key = 0
    plaintext = 0
    #plaintext = 0xFFFFFFFF
    #plaintext = 0xFFFFFFFFFFFF
    plaintext = 0xFFFFFFFFFFFFFFFF

    myKATAN = KATAN(key, 64)

    print 'key =', hex(key)
    print 'plain =', hex(plaintext)

    encrypted = myKATAN.enc(plaintext)
    print 'encrypted =', hex(encrypted)
    decrypted = myKATAN.dec(encrypted)
    print 'decrypted =', hex(decrypted)
