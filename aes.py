#!/usr/bin/python3
consts=[99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22,82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37,114,248,246,100,134,104,152,22,212,164,92,204,93,101,182,146,108,112,72,80,253,237,185,218,94,21,70,87,167,141,157,132,144,216,171,0,140,188,211,10,247,228,88,5,184,179,69,6,208,44,30,143,202,63,15,2,193,175,189,3,1,19,138,107,58,145,17,65,79,103,220,234,151,242,207,206,240,180,230,115,150,172,116,34,231,173,53,133,226,249,55,232,28,117,223,110,71,241,26,113,29,41,197,137,111,183,98,14,170,24,190,27,252,86,62,75,198,210,121,32,154,219,192,254,120,205,90,244,31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125,2,3,1,1,1,2,3,1,1,1,2,3,3,1,1,2,14,11,13,9,9,14,11,13,13,9,14,11,11,13,9,14,0,1,2,4,8,16,32,64,128,27,54]
BLOCK_SIZE, Nr, Nb, Nk = 128, 10, 4, 4
sbox, isbox = [consts[i:i+16] for i in range(0,256,16)], [consts[i:i+16] for i in range(256,512,16)]
mcs, imcs, rcon = consts[512:528], consts[528:544], consts[544:]

def uint32(arr): return int.from_bytes(arr, "big") # [byte,byte,byte,byte] -> uint32
def uint32_bytes(ui32): return list(int.to_bytes(ui32, 4, "big")) # uint32 -> [byte,byte,byte,byte]
def foreach_in_state(state, fn): state[:] = [[fn(r, c) for c in range(Nb)] for r in range(Nk)]
def rotate_R32(ui32, bits): return ((ui32 >> bits) | (ui32 << (32 - bits))) & 0xff_ff_ff_ff
def sub_byte(box, byte): return box[byte >> 4][byte & 0xf]
def sub_word(box, ui32): return uint32([sub_byte(box, byte) for byte in uint32_bytes(ui32)])
def add_round_key(state, wbs): foreach_in_state(state, lambda r, c: state[r][c] ^ wbs[r * Nk + c])
def mix_columns(state, inv=False): state[:] = [mix_column(state[r], inv) for r in range(Nk)]

def sub_bytes(state, inv=False):
  box = sbox if not inv else isbox
  foreach_in_state(state, lambda r, c: sub_byte(box, state[r][c]))

def gmul(a, b, p=0, i=8):
  if a == 1: return b
  if i == 0: return p & 0xff
  return gmul((a<<1) ^ (0x1b if a & 0x80 else 0), b>>1, p^(a if b & 1 else 0), i-1)

def mix_column(c, inv=False):
  m = mcs if not inv else imcs
  return [gmul(m[0x0], c[0]) ^ gmul(m[0x1], c[1]) ^ gmul(m[0x2], c[2]) ^ gmul(m[0x3], c[3]),
          gmul(m[0x4], c[0]) ^ gmul(m[0x5], c[1]) ^ gmul(m[0x6], c[2]) ^ gmul(m[0x7], c[3]),
          gmul(m[0x8], c[0]) ^ gmul(m[0x9], c[1]) ^ gmul(m[0xa], c[2]) ^ gmul(m[0xb], c[3]),
          gmul(m[0xc], c[0]) ^ gmul(m[0xd], c[1]) ^ gmul(m[0xe], c[2]) ^ gmul(m[0xf], c[3])]

def shift_rows(state, inv=False):
  copy = [e[:] for e in state]
  foreach_in_state(state, lambda r, c: copy[(r+c if not inv else r-c) % Nk][c])

def key_expansion(key):
  ksb = [0] * (Nb * (Nr + 1)) # uint32[n]
  for i in range(len(ksb)):
    if i < Nk:
      ksb[i] = uint32([key[Nb*i], key[Nb*i+1], key[Nb*i+2], key[Nb*i+3]])
    else:
      temp = ksb[i - 1]
      if not i % Nk:
        temp = sub_word(sbox, rotate_R32(temp, 24)) ^ (rcon[i // Nk] << 24)
      elif Nk > 6 and i % Nk == 4:
        temp = sub_word(sbox, temp)
      ksb[i] = ksb[i - Nk] ^ temp
  return [byte for ui32 in ksb for byte in uint32_bytes(ui32)] # -> byte[n * 4]

def cipher(state, ks):
  add_round_key(state, ks[0:Nb*4])
  for r in range(1, Nr+1):
    sub_bytes(state)
    shift_rows(state)
    if r < Nr: mix_columns(state)
    add_round_key(state, ks[r*Nb*4:(r+1)*Nb*4])

def inv_cipher(state, ks):
  add_round_key(state, ks[Nr*Nb*4:(Nr+1)*Nb*4])
  for r in range(Nr-1, -1, -1):
    shift_rows(state, True)
    sub_bytes(state, True)
    add_round_key(state, ks[r*Nb*4:(r+1)*Nb*4])
    if r: mix_columns(state, True)
