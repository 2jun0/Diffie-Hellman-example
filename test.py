from argparse import ArgumentParser
parser = ArgumentParser(description='디피-헬만 키 생성 프로그램')
parser.add_argument('--nbytes', required=True, type=int)

from key import SecretKey, generate_private_key, generate_public_key, generate_secret_key
import key

from Crypto.Cipher import DES
def encrypt_DES(text: str, key: SecretKey) -> bytes:
  while len(text) % 8 != 0:
    text += b'\x00'

  des = DES.new(key.to_bytes(), DES.MODE_ECB)
  return des.encrypt(text)

def decrypt_DES(encrypted: str, key: SecretKey) -> bytes:
  des = DES.new(key.to_bytes(), DES.MODE_ECB)
  decrypted = des.decrypt(encrypted)

  return decrypted.rstrip(b'\x00')

def read_file(path: str) -> str:
  text = b''
  try:
    rf = open(path, 'rb')
    tmp = rf.read(1024)
    while tmp != b'':
      text += tmp
      tmp = rf.read(1024)
  finally:
    rf.close()

  return text

def save_file(path: str, text: str):
  try:
    wf = open(path, 'wb')
    text = wf.write(text)
  finally:
    wf.close()

  return text

if __name__ == '__main__':
  args = parser.parse_args()
  nbytes = args.nbytes

  # 엘리스와 밥의 nbytes 크기인 개인키 생성 
  Alice_pri_key = generate_private_key(nbytes, 10556253568756343647, 5)
  Bob_pri_key = generate_private_key(nbytes, 10556253568756343647, 5)

  print(f'사용된 소수: {Alice_pri_key.q}, 소수의 원시근: {Alice_pri_key.a}')

  print('[엘리스와 밥의 개인키]\n'
        f'엘리스\'s 개인키 : {Alice_pri_key}\n'
        f'밥\'s 개인키 : {Bob_pri_key}\n')

  # 엘리스와 밥의 공개키 생성
  Alice_pub_key = generate_public_key(pri_key=Alice_pri_key)
  Bob_pub_key = generate_public_key(pri_key=Bob_pri_key)

  print('[엘리스와 밥의 공개키]\n'
        f'엘리스\'s 공개키 : {Alice_pub_key}\n'
        f'밥\'s 공개키 : {Bob_pub_key}\n')

  # 엘리스와 밥의 비밀키 생성
  Alice_sec_key = generate_secret_key(my_pri_key=Alice_pri_key, other_pub_key=Bob_pub_key)
  Bob_sec_key = generate_secret_key(my_pri_key=Bob_pri_key, other_pub_key=Alice_pub_key)

  print('[엘리스와 밥의 비밀키]\n'
        f'엘리스\'s 비밀키 : {Alice_sec_key}\n'
        f'밥\'s 비밀키 : {Bob_sec_key}\n')

  print('비밀키가 일치하는가? : %s' % (Alice_sec_key.val == Bob_sec_key.val))

  # 엘리스는 어린왕자 파일 전송
  Alice_text = read_file('alice\'s 어린왕자.txt')
  encrypted = encrypt_DES(Alice_text, Alice_sec_key)
  # 밥은 어린왕자 파일 저장
  Bob_text = decrypt_DES(encrypted, Bob_sec_key)
  save_file('Bob\'s 어린왕자.txt', Bob_text)
  print('[파일 전송 완료!]')
  