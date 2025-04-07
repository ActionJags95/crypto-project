from random import randint

def string_to_binary(text):
  return ''.join(format(ord(char), '08b') for char in text)

def binary_to_string(binaryString):
  chars = [binaryString[i:i+8] for i in range(0, len(binaryString), 8)]
  return ''.join(chr(int(char, 2)) for char in chars)

def xor_strings(left, right):
  return ''.join(str(int(a) ^ int(b)) for a, b in zip(left, right))

def feistel_function(right, key):
  right_int = int(right, 2)
  key_int = int(key, 2)
  mod_sum = (right_int + key_int) % (2 ** len(right))
  return format(mod_sum, f'0{len(right)}b')

def feistel_round(left, right, key):
  feistelResult = feistel_function(right, key)
  newLeft = right
  newRight = xor_strings(left, feistelResult)
  return newLeft, newRight

def generate_keys(initialKey, numRounds, keyLength):
  keys = [initialKey]
  for i in range(1, numRounds):
    prevKey = keys[-1]
    rotatedKey = prevKey[i % keyLength:] + prevKey[:i % keyLength]
    keys.append(rotatedKey)
  return keys

def feistel_encrypt(text, initialKey, numRounds):
  binaryText = string_to_binary(text)
  if len(binaryText) % 2 != 0:
    binaryText += '0'
    
  halfLength = len(binaryText) // 2
  left, right = binaryText[:halfLength], binaryText[halfLength:]
  keys = generate_keys(initialKey, numRounds, len(initialKey))

  for key in keys:
    left, right = feistel_round(left, right, key)
    encString = right + left
    print(f'Round: {keys.index(key)+1}, Cipher text: {binary_to_string(encString)}')
    
  encryptedBinary = right + left
  return binary_to_string(encryptedBinary)

def feistel_decrypt(encryptedText, initialKey, numRounds):
  encryptedBinary = string_to_binary(encryptedText)
  halfLength = len(encryptedBinary) // 2
  left, right = encryptedBinary[:halfLength], encryptedBinary[halfLength:]
  keys = generate_keys(initialKey, numRounds, len(initialKey))

  for key in reversed(keys):
    left, right = feistel_round(left, right, key)
    
  decryptedBinary = right + left  # Reverse the final swap
  return binary_to_string(decryptedBinary)

if __name__ == "__main__":
  message = input("Enter the string : ")
  numRounds = int(input("Enter the number of rounds : "))
  keyString = ''.join(chr(ord('a')+randint(0,25)) for i in range(1, len(message)))
  initialKey = string_to_binary(keyString)  # 32-bit binary key

  encryptedText = feistel_encrypt(message, initialKey, numRounds)
  print("Encrypted:", repr(encryptedText))

  decryptedText = feistel_decrypt(encryptedText, initialKey, numRounds)
  print("Decrypted:", decryptedText)
