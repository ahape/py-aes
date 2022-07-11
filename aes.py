#!/usr/bin/python3
BLOCK_SIZE = 128
Nr = 10
Nb = 4
Nk = 4

def flatten(arr2d): return [el for arr in arr2d for el in arr]
def word(arr): return int.from_bytes(arr, "big") # [byte,byte,byte,byte] -> uint32
def word_bytes(w): return list(int.to_bytes(w, 4, "big")) # uint32 -> [byte,byte,byte,byte]
def rotate_R32(i32, s): return ((i32>>s) | (i32<<(32-s))) & 0xff_ff_ff_ff
def rotate_L8(i8, s): return ((i8<<s) | (i8>>(8-s))) & 0xff
def array(arr_len, seed=[]): return (seed + ([0]*arr_len))[:arr_len]
def array2d(matrix_len, seed=[]):
  sq = matrix_len ** 2
  arr = array(sq, seed)
  return [arr[i:i+matrix_len] for i in range(0, sq, matrix_len)]

Rcon, p_rcon = [0], 1
for _ in range(10):
  Rcon += [p_rcon << (6*4)] # Programmatically build Rcon
  p_rcon = (p_rcon<<1) ^ (0x11b & -(p_rcon>>7))

sbox, p, q = array2d(16, [0x63]), 1, 1
while True:
  p = (p ^ (p << 1) & 0xff) ^ (0x1b if p & 0x80 else 0)
  for s in [1, 2, 4]:
    q ^= (q << s) & 0xff
  q ^= 0x09 if q & 0x80 else 0
  sbox[p//16][p%16] = q ^ rotate_L8(q,1) ^ rotate_L8(q,2) ^ rotate_L8(q,3) ^ rotate_L8(q,4) ^ 0x63
  if p == 1: break

inv_sbox = array2d(16)
for n in range(16*16):
  v = sbox[n >> 4][n & 0xf]
  v = ((((v >> 4) - 1) << 4) & 0xf0) | (((v & 0xf) - 1) & 0xf)
  k = sbox[v >> 4][v & 0xf]
  inv_sbox[k >> 4][k & 0xf] = v

def sub_bytes(state, inv=False):
  box = sbox if not inv else inv_sbox
  tmp = array2d(4)
  for r in range(Nk):
    for c in range(Nb):
      tmp[r][c] = box[state[r][c] >> 4][state[r][c] & 0xf]
  state[:] = tmp[:]

def sub_word(w):
  wbs, o_wbs = word_bytes(w), []
  for byte in wbs:
    o_wbs += [sbox[byte >> 4][byte & 0xf]]
  return word(o_wbs)

def add_round_key(s, ws):
  wbs = [*map(word_bytes, ws)]
  for r in range(Nk):
    for c in range(Nb):
      s[r][c] ^= wbs[r][c]

def gmul(a, b):
  p = 0
  for i in range(8):
    if b & 1:
      p ^= a
    hi_bit = a & 0x80
    a <<= 1
    a &= 0xff
    if hi_bit:
      a ^= 0x1b
    b >>= 1
  return p & 0xff

def mix_column(col): return [
  gmul(0x02, col[0]) ^ gmul(0x03, col[1]) ^ col[2] ^ col[3],
  col[0] ^ gmul(0x02, col[1]) ^ gmul(0x03, col[2]) ^ col[3],
  col[0] ^ col[1] ^ gmul(0x02, col[2]) ^ gmul(0x03, col[3]),
  gmul(0x03, col[0]) ^ col[1] ^ col[2] ^ gmul(0x02, col[3])]

def inv_mix_column(col): return [
  gmul(0x0e, col[0]) ^ gmul(0x0b, col[1]) ^ gmul(0x0d, col[2]) ^ gmul(0x09, col[3]),
  gmul(0x09, col[0]) ^ gmul(0x0e, col[1]) ^ gmul(0x0b, col[2]) ^ gmul(0x0d, col[3]),
  gmul(0x0d, col[0]) ^ gmul(0x09, col[1]) ^ gmul(0x0e, col[2]) ^ gmul(0x0b, col[3]),
  gmul(0x0b, col[0]) ^ gmul(0x0d, col[1]) ^ gmul(0x09, col[2]) ^ gmul(0x0e, col[3])]

def mix_columns(s, inv=False):
  for c in range(Nb):
    s[c] = mix_column(s[c]) if not inv else inv_mix_column(s[c])

def shift_rows(s, inv=False): # Dunno why this is shifting the COLS instead of the ROWS?
  def shift_n_times(col, n):
    for _ in range(n):
      part = col[:1] if not inv else col[-1:]
      col[:] = (col[1:] + part) if not inv else (part + col[:-1])
    return col
  o = array2d(4)
  for i in range(Nk):
    o[0][i],o[1][i],o[2][i],o[3][i] = shift_n_times([s[0][i],s[1][i],s[2][i],s[3][i]], i)
  s[:] = o[:]

def key_expansion(key, w=[0]*(Nb*(Nr+1))):
  i = 0
  while i < Nb * (Nr+1):
    if i < Nk:
      w[i] = word([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]])
    else:
      temp = w[i-1]
      if i % Nk == 0:
        temp = sub_word(rotate_R32(temp, 6*4)) ^ Rcon[i//Nk]
      elif Nk > 6 and i % Nk == 4:
        temp = sub_word(temp)
      w[i] = w[i-Nk] ^ temp
    i += 1
  return [*map(word_bytes, w)]

def cipher(state, w):
  add_round_key(state, w[0:Nb])
  for r in range(1, Nr):
    sub_bytes(state)
    shift_rows(state)
    mix_columns(state)
    add_round_key(state, w[r*Nb:(r+1)*Nb])
  sub_bytes(state)
  shift_rows(state)
  add_round_key(state, w[Nr*Nb:(Nr+1)*Nb])

def inv_cipher(state, w):
  add_round_key(state, w[Nr*Nb:(Nr+1)*Nb])
  for r in range(Nr-1, 0, -1):
    shift_rows(state, True)
    sub_bytes(state, True)
    add_round_key(state, w[r*Nb:(r+1)*Nb])
    mix_columns(state, True)
  shift_rows(state, True)
  sub_bytes(state, True)
  add_round_key(state, w[0:Nb])

# TESTING ======================================================================

def key_schedules(key_or_partial):
  return [*map(word, key_expansion(array(16, key_or_partial)))]

def encrypt(value, key):
  if type(value) == str:
    value = text_to_block(value)
  state = array2d(4, value)
  result = cipher(state, key_schedules(key))
  return flatten(state)

def decrypt(value, key):
  state = array2d(4, value)
  result = inv_cipher(state, key_schedules(key))
  return flatten(state)

def text_to_block(txt):
  arr = list(txt.encode("utf8"))
  pad = (BLOCK_SIZE // 8) - len(arr) % (BLOCK_SIZE // 8)
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

import os

DEBUG = os.getenv("DEBUG") == "true"

if DEBUG:
  assert gmul(0x57, 0x13) == 0xfe
  print("Galois Field multiplication works")

  a = mix_column([242, 10, 34, 92])
  b = mix_column([219, 19, 83, 69])
  c = mix_column([1, 1, 1, 1])
  d = mix_column([198, 198, 198, 198])
  e = mix_column([212, 212, 212, 213])
  f = mix_column([45, 38, 49, 76])
  assert [159, 220, 88, 157] == a, a
  assert [142, 77, 161, 188] == b, b
  assert [1, 1, 1, 1] == c, c
  assert [198, 198, 198, 198] == d, d
  assert [213, 213, 215, 214] == e, e
  assert [77, 126, 189, 248] == f, f
  print("mix_column() works")

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
  actual = flatten(key_expansion([0]*16))
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
  actual = flatten(key_expansion([0xff]*16))
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
  actual = flatten(key_expansion(parse_hex_array("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f")))
  assert expected == actual, f"{expected} != {actual}"

  print("key_expansion() works")

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
    result = encrypt(test[0], test[1])
    assert result == test[2], f"{test[2]} != {result}"

  print("cipher() works")

  tests = [
      (
        parse_hex_joined("69c4e0d86a7b0430d8cdb78070b4c55a"),# input
        parse_hex_joined("000102030405060708090a0b0c0d0e0f"),# key
        parse_hex_joined("00112233445566778899aabbccddeeff") # output
      ),
      (
        parse_hex_joined("AE5BF2DBE2A958E142216D6E275DE9D1"),
        list(b"x"*16),
        text_to_block("hello"),
      )
  ]
  for test in tests:
    result = decrypt(test[0], test[1])
    assert result == test[2], f"{test[2]} != {result}"

  print("inv_cipher() works")

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
