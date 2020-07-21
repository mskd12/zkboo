from Crypto.Cipher import AES

BLOCK_SIZE = 16

# pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
# unpad = lambda s: s[:-ord(s[len(s) - 1:])]

key_raw = "B6F1380942BD9401339F7F6F09353730"
iv_raw = "9C7BF0CC70BA60E4FA2C6ADE205DD8FB"
plaintext_raw = "B66643139446DE482E576B18D489865D5D5B261617A1699A130A766ED837B92E0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F"

key = key_raw.decode("hex")
iv = iv_raw.decode("hex")
plaintext = plaintext_raw.decode("hex")

cipher = AES.new(key, AES.MODE_CBC, iv)
print(cipher.encrypt(plaintext).encode("hex"))