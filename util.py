import os
import random

def get_bytes_length(val: int) -> int:
  x, r = divmod(val.bit_length(), 8)
  if r:
    return x+1
  else:
    return x

def get_random_bytes(nbytes: int) -> bytes:
  # Get the random bytes
  random_bytes = os.urandom(nbytes)
  
  return random_bytes

def get_random_int(nbytes: int) -> int:
  random_bytes = get_random_bytes(nbytes)
  random_int = int.from_bytes(random_bytes, 'big')

  # Ensure that the number is large enough to just fill out the required
  # number of bits.
  # ex) nbytes = 1
  # random_int = 00011010
  # 00011010 | 10000000  =>  10011010
  random_int |= 1 << (int(nbytes/8) - 1)

def get_random_odd_int(nbytes: int) -> int:
  random_int = get_random_int(nbytes)

  # Make sure it's odd
  return random_int | 1