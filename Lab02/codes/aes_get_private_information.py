from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random
import os

# 生成对称密钥 k
key = os.urandom(16)  # AES 密钥长度为 16 字节（128 位）

# 服务器端保存的明文消息列表
message_list = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
length = len(message_list)

# 服务器端使用对称密钥 k 对消息进行加密
ciphertext_list = []
for message in message_list:
    # 将消息转换为字节类型
    message_bytes = str(message).encode('utf-8')
    # 创建 AES 加密器
    cipher = AES.new(key, AES.MODE_ECB)
    # 填充消息
    padded_message = pad(message_bytes, AES.block_size)
    # 加密消息
    ciphertext = cipher.encrypt(padded_message)
    ciphertext_list.append(ciphertext)

# 客户端随机选择一个要读的位置
pos = random.randint(0, length - 1)
print("要读取的数值位置为：", pos)

# 服务器将指定位置的密文发送给客户端
selected_ciphertext = ciphertext_list[pos]

# 客户端使用对称密钥 k 对密文进行解密
decipher = AES.new(key, AES.MODE_ECB)
# 解密密文
decrypted_bytes = decipher.decrypt(selected_ciphertext)
# 去除填充
unpadded_bytes = unpad(decrypted_bytes, AES.block_size)
# 将字节类型转换为整数
decrypted_message = int(unpadded_bytes.decode('utf-8'))

print("得到数值：", decrypted_message)