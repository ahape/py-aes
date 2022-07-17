#!/usr/bin/python3
from aes import Aes

def chunks(arr, csize): return [arr[i:i+csize] for i in range(0, len(arr), csize)]
def flatten(arr2d): return [el for arr in arr2d for el in arr]
def array(al, init=[]): return (init + ([0] * al))[:al]
def rotate_L8(i8, s): return ((i8<<s) | (i8>>(8-s))) & 0xff
def array2d(ml, init=[]): return chunks(array(ml ** 2, init), ml)
# Programmatically build rcon
Rcon2, p_rcon = [0], 1
for _ in range(10):
  Rcon2 += [p_rcon << (6*4)]
  p_rcon = (p_rcon<<1) ^ (0x11b & -(p_rcon>>7))

# Programmatically build sbox
sbox2, p, q = array2d(16, [0x63]), 1, 1
while True:
  p = (p ^ (p << 1) & 0xff) ^ (0x1b if p & 0x80 else 0)
  for s in [1, 2, 4]:
    q ^= (q << s) & 0xff
  q ^= 0x09 if q & 0x80 else 0
  sbox2[p//16][p%16] = q ^ rotate_L8(q,1) ^ rotate_L8(q,2) ^ rotate_L8(q,3) ^ rotate_L8(q,4) ^ 0x63
  if p == 1: break

# Programmatically build inverse sbox
inv_sbox2 = array2d(16)
for n in range(16*16):
  v = sbox2[n >> 4][n & 0xf]
  v = ((((v >> 4) - 1) << 4) & 0xf0) | (((v & 0xf) - 1) & 0xf)
  k = sbox2[v >> 4][v & 0xf]
  inv_sbox2[k >> 4][k & 0xf] = v

class Crypto(Aes):
  def __init__(self, block_size):
    super().__init__(block_size)

  def key_schedules(self, key_or_partial):
    if type(key_or_partial[0]) == list:
      key_or_partial = flatten(key_or_partial)
    return self.key_expansion(array(16, key_or_partial))

  def encrypt(self, value, key):
    if type(value) == str:
      value = self.text_to_block(value)
    state = array2d(4, value)
    result = self.cipher(state, self.key_schedules(key))
    return flatten(state)

  def decrypt(self, value, key):
    state = array2d(4, value)
    result = self.inv_cipher(state, self.key_schedules(key))
    return flatten(state)

  def text_to_block(self, txt):
    arr = list(txt.encode("utf8"))
    pad = (self.BLOCK_SIZE // 8) - len(arr) % (self.BLOCK_SIZE // 8)
    return arr + ([pad]*pad) # pkcs5 style padding

def block_to_text(bs): # TODO: Needs to be more robust
  p = bs[-1]
  for i in range(len(bs)-1, 0, -1):
    b = bs[i]
    if b != p: break
    bs[:] = bs[:-1]
  return bytes(bs).decode("utf8")

def parse_hex_arrays(arr2d):
  return [parse_hex_array(arr) for arr in arr2d]

def parse_hex_array(arr):
  return [int(h, 16) for h in arr.split()]

def parse_hex_joined(joined):
  return [int(joined[i:i+2], 16) for i in range(0,32,2)]

def to_hex_string(arr):
  return "".join([f"{x:x}".zfill(2) for x in arr])

def test_gmul():
  assert Aes.gmul(0x57, 0x13) == 0xfe
  print("Galois Field multiplication works")

def test_mix_column():
  a = Aes.mix_column([242, 10, 34, 92])
  b = Aes.mix_column([219, 19, 83, 69])
  c = Aes.mix_column([1, 1, 1, 1])
  d = Aes.mix_column([198, 198, 198, 198])
  e = Aes.mix_column([212, 212, 212, 213])
  f = Aes.mix_column([45, 38, 49, 76])
  assert [159, 220, 88, 157] == a, a
  assert [142, 77, 161, 188] == b, b
  assert [1, 1, 1, 1] == c, c
  assert [198, 198, 198, 198] == d, d
  assert [213, 213, 215, 214] == e, e
  assert [77, 126, 189, 248] == f, f
  print("mix_column() works")

def test_key_expansion():
  aes = Aes(128)
  expected = flatten(parse_hex_arrays([
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
    "62 63 63 63 62 63 63 63 62 63 63 63 62 63 63 63",
    "9b 98 98 c9 f9 fb fb aa 9b 98 98 c9 f9 fb fb aa",
    "90 97 34 50 69 6c cf fa f2 f4 57 33 0b 0f ac 99",
    "ee 06 da 7b 87 6a 15 81 75 9e 42 b2 7e 91 ee 2b",
    "7f 2e 2b 88 f8 44 3e 09 8d da 7c bb f3 4b 92 90",
    "ec 61 4b 85 14 25 75 8c 99 ff 09 37 6a b4 9b a7",
    "21 75 17 87 35 50 62 0b ac af 6b 3c c6 1b f0 9b",
    "0e f9 03 33 3b a9 61 38 97 06 0a 04 51 1d fa 9f",
    "b1 d4 d8 e2 8a 7d b9 da 1d 7b b3 de 4c 66 49 41",
    "b4 ef 5b cb 3e 92 e2 11 23 e9 51 cf 6f 8f 18 8e",
  ]))
  actual = aes.key_expansion([0]*16)
  assert expected == actual, f"{expected} != {actual}"

  expected = flatten(parse_hex_arrays([
    "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff",
    "e8 e9 e9 e9 17 16 16 16 e8 e9 e9 e9 17 16 16 16",
    "ad ae ae 19 ba b8 b8 0f 52 51 51 e6 45 47 47 f0",
    "09 0e 22 77 b3 b6 9a 78 e1 e7 cb 9e a4 a0 8c 6e",
    "e1 6a bd 3e 52 dc 27 46 b3 3b ec d8 17 9b 60 b6",
    "e5 ba f3 ce b7 66 d4 88 04 5d 38 50 13 c6 58 e6",
    "71 d0 7d b3 c6 b6 a9 3b c2 eb 91 6b d1 2d c9 8d",
    "e9 0d 20 8d 2f bb 89 b6 ed 50 18 dd 3c 7d d1 50",
    "96 33 73 66 b9 88 fa d0 54 d8 e2 0d 68 a5 33 5d",
    "8b f0 3f 23 32 78 c5 f3 66 a0 27 fe 0e 05 14 a3",
    "d6 0a 35 88 e4 72 f0 7b 82 d2 d7 85 8c d7 c3 26",
  ]))
  actual = aes.key_expansion([0xff]*16)
  assert expected == actual, f"{expected} != {actual}"

  expected = flatten(parse_hex_arrays([
    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f",
    "d6 aa 74 fd d2 af 72 fa da a6 78 f1 d6 ab 76 fe",
    "b6 92 cf 0b 64 3d bd f1 be 9b c5 00 68 30 b3 fe",
    "b6 ff 74 4e d2 c2 c9 bf 6c 59 0c bf 04 69 bf 41",
    "47 f7 f7 bc 95 35 3e 03 f9 6c 32 bc fd 05 8d fd",
    "3c aa a3 e8 a9 9f 9d eb 50 f3 af 57 ad f6 22 aa",
    "5e 39 0f 7d f7 a6 92 96 a7 55 3d c1 0a a3 1f 6b",
    "14 f9 70 1a e3 5f e2 8c 44 0a df 4d 4e a9 c0 26",
    "47 43 87 35 a4 1c 65 b9 e0 16 ba f4 ae bf 7a d2",
    "54 99 32 d1 f0 85 57 68 10 93 ed 9c be 2c 97 4e",
    "13 11 1d 7f e3 94 4a 17 f3 07 a7 8b 4d 2b 30 c5",
  ]))
  actual = aes.key_expansion(parse_hex_array("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"))
  assert expected == actual, f"{expected} != {actual}"
  print("key_expansion() works")


def test_128_encrypt():
  crypto = Crypto(128)
  tests = [
      ( # Example from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
        parse_hex_joined("00112233445566778899aabbccddeeff"),# input
        parse_hex_joined("000102030405060708090a0b0c0d0e0f"),# key
        parse_hex_joined("69c4e0d86a7b0430d8cdb78070b4c55a") # output
      ),
      (
        "hello",
        list(b"x"*16),
        parse_hex_joined("AE5BF2DBE2A958E142216D6E275DE9D1"),
      )
  ]
  for test in tests:
    result = crypto.encrypt(test[0], test[1])
    assert result == test[2], f"{test[2]} != {result}"

  print("cipher(128) works")

def test_128_decrypt():
  crypto = Crypto(128)
  tests = [
      (
        parse_hex_joined("69c4e0d86a7b0430d8cdb78070b4c55a"),# input
        parse_hex_joined("000102030405060708090a0b0c0d0e0f"),# key
        parse_hex_joined("00112233445566778899aabbccddeeff") # output
      ),
      (
        parse_hex_joined("AE5BF2DBE2A958E142216D6E275DE9D1"),
        list(b"x"*16),
        crypto.text_to_block("hello"),
      )
  ]
  for test in tests:
    result = crypto.decrypt(test[0], test[1])
    assert result == test[2], f"{test[2]} != {result}"

  print("inv_cipher(128) works")

import os

DEBUG = os.getenv("DEBUG") == "true"

if DEBUG:
  test_gmul()
  test_mix_column()
  test_key_expansion()
  test_128_encrypt()
  test_128_decrypt()


# Definitions:
# Word: 32 bits or 4 bytes
# Nb=4 then round key = 128 bits (16 bytes) (4 words)
# Nb: Number of columns (aka words)
# Nk: Number of words comprising of the cipher key. Can be 4, 6, 8 (maybe (implicitly) number of rows?)
# Nr: Number of rounds (which is a fn of Nb and Nk (fixed)). Can be 10, 12, 14
# Block: Seq of bits via input, output, state, round key. Length is same length as key (128,192,256)
# State: 2d array. If 128 key len, then 4x4 (byte array).
# https://crypto.stackexchange.com/questions/2402/how-to-solve-mixcolumns/2403#2403
# https://www.samiam.org/key-schedule.html
#
# Notes:
# In the documentation, word[x,y] means SLICE
