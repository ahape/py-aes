#!/usr/bin/python3
BLOCK_SIZE, Nr, Nb, Nk = 128, 10, 4, 4
def flatten(arr2d): return [el for arr in arr2d for el in arr]
def chunks(arr, csize): return [arr[i:i + csize] for i in range(0, len(arr), csize)]
def word(arr): return int.from_bytes(arr, "big") # [byte,byte,byte,byte] -> uint32
def word_bytes(w): return list(int.to_bytes(w, 4, "big")) # uint32 -> [byte,byte,byte,byte]
def rotate_R32(i32, s): return ((i32>>s) | (i32<<(32-s))) & 0xff_ff_ff_ff
def array(arr_len, seed=[]): return (seed + ([0]*arr_len))[:arr_len]
def array2d(mtx_len, seed=[]): return chunks(array(mtx_len**2, seed), mtx_len)
def sub_byte(box, byte): return box[byte >> 4][byte & 0xf]
def sub_word(w): return word([sub_byte(sbox, byte) for byte in word_bytes(w)])
def add_round_key(state, wbs): s_mtx_fn(state, lambda r, c: state[r][c] ^ wbs[r*Nk+c])
def unzip_hex(zh, mtx_len): return chunks([int(zh[i:i+2], 16) for i in range(0, len(zh), 2)], mtx_len)

def mix_columns(state, inv=False):
  for c in range(Nb): state[c] = mix_column(state[c], inv)

def s_mtx_fn(state, fn):
  for r, c in [(i // Nk, i % Nb) for i in range(Nk * Nb)]:
    state[r][c] = fn(r, c)

def sub_bytes(state, inv=False):
  box = sbox if not inv else inv_sbox
  s_mtx_fn(state, lambda r, c: sub_byte(box, state[r][c]))

def gmul(a, b, p=0):
  if a == 1: return b
  for i in range(8):
    p ^= a if b & 1 else 0
    a = (a << 1) & 0xff ^ (0x1b if a & 0x80 else 0)
    b >>= 1
  return p & 0xff

def mix_column(c, inv=False):
  mtx = mc_mtx if not inv else inv_mc_mtx
  return [gmul(mtx[0][0], c[0]) ^ gmul(mtx[0][1], c[1]) ^ gmul(mtx[0][2], c[2]) ^ gmul(mtx[0][3], c[3]),
          gmul(mtx[1][0], c[0]) ^ gmul(mtx[1][1], c[1]) ^ gmul(mtx[1][2], c[2]) ^ gmul(mtx[1][3], c[3]),
          gmul(mtx[2][0], c[0]) ^ gmul(mtx[2][1], c[1]) ^ gmul(mtx[2][2], c[2]) ^ gmul(mtx[2][3], c[3]),
          gmul(mtx[3][0], c[0]) ^ gmul(mtx[3][1], c[1]) ^ gmul(mtx[3][2], c[2]) ^ gmul(mtx[3][3], c[3])]

def shift_rows(s, inv=False): # Dunno why this is shifting the COLS instead of the ROWS?
  def shift_n_times(col, n):
    for _ in range(n):
      part = col[:1] if not inv else col[-1:]
      col[:] = (col[1:] + part) if not inv else (part + col[:-1])
    return col
  for i in range(Nk):
    s[0][i],s[1][i],s[2][i],s[3][i] = shift_n_times([s[0][i],s[1][i],s[2][i],s[3][i]], i)

def key_expansion(key, ks=[0]*(Nb*(Nr+1))):
  for i in range(Nb * (Nr + 1)):
    if i < Nk:
      ks[i] = word([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]])
    else:
      temp = ks[i-1]
      if not i % Nk:
        temp = sub_word(rotate_R32(temp, 6*4)) ^ rcon[i//Nk]
      elif Nk > 6 and i % Nk == 4:
        temp = sub_word(temp)
      ks[i] = ks[i-Nk] ^ temp
  return flatten([word_bytes(w) for w in ks])

def cipher(state, ks):
  add_round_key(state, ks[0:Nb*4])
  for r in range(1, Nr):
    sub_bytes(state)
    shift_rows(state)
    mix_columns(state)
    add_round_key(state, ks[r*Nb*4:(r+1)*Nb*4])
  sub_bytes(state)
  shift_rows(state)
  add_round_key(state, ks[Nr*Nb*4:(Nr+1)*Nb*4])

def inv_cipher(state, ks):
  add_round_key(state, ks[Nr*Nb*4:(Nr+1)*Nb*4])
  for r in range(Nr-1, 0, -1):
    shift_rows(state, True)
    sub_bytes(state, True)
    add_round_key(state, ks[r*Nb*4:(r+1)*Nb*4])
    mix_columns(state, True)
  shift_rows(state, True)
  sub_bytes(state, True)
  add_round_key(state, ks[0:Nb*4])

rcon = [(x << 24) for x in flatten(unzip_hex("0001020408102040801b36", 1))]
sbox = unzip_hex("637C777BF26B6FC53001672BFED7AB76CA82C97DFA5947F0ADD4A2AF9CA472C0B7FD9326363FF7CC34A5E5F171D8311504C723C31896059A071280E2EB27B27509832C1A1B6E5AA0523BD6B329E32F8453D100ED20FCB15B6ACBBE394A4C58CFD0EFAAFB434D338545F9027F503C9FA851A3408F929D38F5BCB6DA2110FFF3D2CD0C13EC5F974417C4A77E3D645D197360814FDC222A908846EEB814DE5E0BDBE0323A0A4906245CC2D3AC629195E479E7C8376D8DD54EA96C56F4EA657AAE08BA78252E1CA6B4C6E8DD741F4BBD8B8A703EB5664803F60E613557B986C11D9EE1F8981169D98E949B1E87E9CE5528DF8CA1890DBFE6426841992D0FB054BB16", 16)
inv_sbox = unzip_hex("52096AD53036A538BF40A39E81F3D7FB7CE339829B2FFF87348E4344C4DEE9CB547B9432A6C2233DEE4C950B42FAC34E082EA16628D924B2765BA2496D8BD12572F8F66486689816D4A45CCC5D65B6926C704850FDEDB9DA5E154657A78D9D8490D8AB008CBCD30AF7E45805B8B34506D02C1E8FCA3F0F02C1AFBD0301138A6B3A9111414F67DCEA97F2CFCEF0B4E67396AC7422E7AD3585E2F937E81C75DF6E47F11A711D29C5896FB7620EAA18BE1BFC563E4BC6D279209ADBC0FE78CD5AF41FDDA8338807C731B11210592780EC5F60517FA919B54A0D2DE57A9F93C99CEFA0E03B4DAE2AF5B0C8EBBB3C83539961172B047EBA77D626E169146355210C7D", 16)
mc_mtx = unzip_hex("02030101010203010101020303010102", 4)
inv_mc_mtx = unzip_hex("0e0b0d09090e0b0d0d090e0b0b0d090e", 4)
