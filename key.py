import os
from util import get_bytes_length

# PRIME
PRIME_1024 = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF
# PRIMITIVE ROOT
ROOT = 2

class Key:
  __slots__ = ['val']
  def __init__(self, val:int):
    self.val = val

  def to_bytes(self) -> bytes:
    nbytes = get_bytes_length(self.val)
    return self.val.to_bytes(nbytes, byteorder='big')

class PrivateKey(Key):
  def __init__(self, val:int, q:int, a: int):
    super().__init__(val)
    self.q = q
    self.a = a

  def __str__(self) -> str:
    return f'PrivateKey(val = {self.val})'

class PublicKey(Key):
  def __init__(self, val:int):
    super().__init__(val)

  def __str__(self) -> str:
    return f'PublicKey(val = {self.val})'

class SecretKey(Key):
  def __init__(self, val:int):
    super().__init__(val)
  
  def __str__(self) -> str:
    return f'SecretKey(val = {self.val})'

def generate_secret_key(my_pri_key: PrivateKey, other_pub_key: PublicKey) -> SecretKey:
  # Generate secret key
  k = pow(other_pub_key.val, my_pri_key.val, my_pri_key.q)

  return SecretKey(k)

def generate_public_key(pri_key: PrivateKey) -> PublicKey:
  # Generate public key value
  y = pow(pri_key.a, pri_key.val, pri_key.q)

  return PublicKey(y)

def generate_private_key(nbytes: int, q: int = PRIME_1024, a: int = ROOT) -> PrivateKey:
  q_nbytes = get_bytes_length(q)

  # 생성하려는 바이트 크기는 최대 prime number의 바이트 크기 보다 1바이트 더 작아야 한다.
  if q_nbytes <= nbytes:
    raise OverflowError('%i bytes are max for q_nbytes,'
                        ' but %i bytes are too big' % (q_nbytes-1, nbytes))

  # Generate private key value
  bytes_val = os.urandom(nbytes)
  x = int.from_bytes(bytes=bytes_val, byteorder='big')

  return PrivateKey(x, q, a)