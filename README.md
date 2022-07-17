# tiny-aes

Basically translating the pseudocode from [this paper](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf) into python. The challenge is to not use any imports, make it as small as possible, and to keep things "pythonic". (Not really worried about it being [fast](https://github.com/nateware/fast-aes/blob/master/ext/fast_aes.c).)

## Usage

```py
from aes import Aes
aes = Aes(128) # Can also be 192 or 256

plaintext = b"this is 16 bytes"
key = b"also is 16 bytes"
ciphertext = aes.cipher(plaintext, key)
# then later on...
plaintext = aes.inv_cipher(ciphertext, key)
```
