#!/usr/bin/python3
consts=[99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22,82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37,114,248,246,100,134,104,152,22,212,164,92,204,93,101,182,146,108,112,72,80,253,237,185,218,94,21,70,87,167,141,157,132,144,216,171,0,140,188,211,10,247,228,88,5,184,179,69,6,208,44,30,143,202,63,15,2,193,175,189,3,1,19,138,107,58,145,17,65,79,103,220,234,151,242,207,206,240,180,230,115,150,172,116,34,231,173,53,133,226,249,55,232,28,117,223,110,71,241,26,113,29,41,197,137,111,183,98,14,170,24,190,27,252,86,62,75,198,210,121,32,154,219,192,254,120,205,90,244,31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125,2,3,1,1,1,2,3,1,1,1,2,3,3,1,1,2,14,11,13,9,9,14,11,13,13,9,14,11,11,13,9,14,0,1,2,4,8,16,32,64,128,27,54]

class Aes:
  Rcon, BS, bsr = [(n << 24) for n in consts[544:]], 4, range(4) # BS=State matrix length
  Sbox = [consts[i:i+16] for i in range(0,256,16)]
  iSbox = [consts[i:i+16] for i in range(256,512,16)]
  mc_mult_mtx, imc_mult_mtx = consts[512:528], consts[528:544] # flattened matrices

  def __init__(self, block_size):
    self.BLOCK_SIZE = block_size # Bits in key (8 * Nb * Nk)
    self.Nb = 4 # Columns in key md array
    self.Nr = 14 if block_size == 256 else 12 if block_size == 192 else 10 # Rounds in cipher
    self.Nk = 8 if block_size == 256 else 6 if block_size == 192 else 4 # Rows in key md array

  def uint32(arr): return int.from_bytes(arr, "big") # [byte,byte,byte,byte] -> uint32
  def uint32_bytes(ui32): return list(int.to_bytes(ui32, 4, "big")) # uint32 -> [byte,byte,byte,byte]
  def rotate_R32(ui32, bits): return ((ui32 >> bits) | (ui32 << (32 - bits))) & 0xff_ff_ff_ff
  def sub_byte(box, byte): return box[byte >> 4][byte & 0xf]
  def sub_word(box, ui32): return Aes.uint32([Aes.sub_byte(box, byte) for byte in Aes.uint32_bytes(ui32)])
  def mix_columns(state, inv=False): state[:] = [Aes.mix_column(state[r], inv) for r in Aes.bsr]
  def add_round_key(state, wbs): Aes.foreach_in_state(state, lambda r, c: state[r][c] ^ wbs[r*Aes.BS+c])
  def foreach_in_state(state, fn): state[:] = [[fn(r, c) for c in Aes.bsr] for r in Aes.bsr]

  def gmul(a, b, p=0, i=8):
    if a == 1: return b
    if i == 0: return p & 0xff
    return Aes.gmul((a<<1) ^ (0x1b if a & 0x80 else 0), b>>1, p^(a if b & 1 else 0), i-1)

  def mix_column(c, inv=False):
    g, m, r = Aes.gmul, Aes.imc_mult_mtx if inv else Aes.mc_mult_mtx, range(0, Aes.BS**2, Aes.BS)
    return [g(m[i],c[0]) ^ g(m[i+1],c[1]) ^ g(m[i+2],c[2]) ^ g(m[i+3],c[3]) for i in r]

  def sub_bytes(state, inv=False):
    box = Aes.iSbox if inv else Aes.Sbox
    Aes.foreach_in_state(state, lambda r, c: Aes.sub_byte(box, state[r][c]))

  def shift_rows(state, inv=False):
    copy = [e[:] for e in state]
    Aes.foreach_in_state(state, lambda r, c: copy[(r-c if inv else r+c) % Aes.BS][c])

  def key_expansion(self, key):
    Nb, Nr, Nk = self.Nb, self.Nr, self.Nk
    ksb = [0] * (Nb * (Nr + 1)) # uint32[n];
    for i in range(len(ksb)):
      if i < Nk:
        ksb[i] = Aes.uint32([key[Nb*i], key[Nb*i+1], key[Nb*i+2], key[Nb*i+3]])
      else:
        temp = ksb[i - 1]
        if not i % Nk:
          temp = Aes.sub_word(Aes.Sbox, Aes.rotate_R32(temp, 24)) ^ (self.Rcon[i // Nk])
        elif Nk > 6 and i % Nk == 4:
          temp = Aes.sub_word(Aes.Sbox, temp)
        ksb[i] = ksb[i - Nk] ^ temp
    return [byte for ui32 in ksb for byte in Aes.uint32_bytes(ui32)] # -> byte[n * 4]

  def cipher(self, state, key):
    ks = self.key_expansion(list(key))
    state = [[int(state[r*Aes.BS+c]) for c in Aes.bsr] for r in Aes.bsr] # Transform into byte matrix
    Nb, Nr, Nk = self.Nb, self.Nr, self.Nk
    Aes.add_round_key(state, ks[0:Nb*4])
    for r in range(1, Nr+1):
      Aes.sub_bytes(state)
      Aes.shift_rows(state)
      if r < Nr: Aes.mix_columns(state) # (r < Nr) = Last iteration
      Aes.add_round_key(state, ks[r*Nb*4:(r+1)*Nb*4])
    return bytes(state[i // Aes.BS][i % Aes.BS] for i in range(Aes.BS**2))

  def inv_cipher(self, state, key):
    ks = self.key_expansion(list(key))
    state = [[int(state[r*Aes.BS+c]) for c in Aes.bsr] for r in Aes.bsr] # Transform into byte matrix
    Nb, Nr, Nk = self.Nb, self.Nr, self.Nk
    Aes.add_round_key(state, ks[Nr*Nb*4:(Nr+1)*Nb*4])
    for r in range(Nr-1, -1, -1):
      Aes.shift_rows(state, True)
      Aes.sub_bytes(state, True)
      Aes.add_round_key(state, ks[r*Nb*4:(r+1)*Nb*4])
      if r: Aes.mix_columns(state, True) # (r == 0) = Last iteration
    return bytes(state[i // Aes.BS][i % Aes.BS] for i in range(Aes.BS**2))
