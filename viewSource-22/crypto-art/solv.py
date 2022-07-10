from PIL import Image
from Crypto.Util.number import bytes_to_long, long_to_bytes
from untwister import *

ref = Image.open('Art_Final_2022.png', 'r').convert('RGBA')
ref_pix = ref.load()

mod = Image.open('ENHANCED_Final_2022.png', 'r').convert('RGBA')
mod_pix = mod.load()

random_nums = []

for i in range(ref.size[0] * ref.size[1]*0+1000):
	x = i % ref.size[0]
	y = i // ref.size[0]
	nums = b"".join([i.to_bytes(1,"little") for i in [bore ^ spice for bore, spice in zip(ref_pix[x, y], mod_pix[x,y])]])
	random_nums.append(bytes_to_long(nums[::-1]))


print(random_nums[0:10])
untwist = untwister()
recovered_state = untwist.untwist(random_nums[:624])

untwist.clone()
x = []
x.extend(untwist.state)
x.append(624)
x=tuple(x)
state= (3, x, None)
#print(state)

"""
for i in range(ref.size[0] * ref.size[1]):
	x = untwist.cloned.get_random_number()
"""
	
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode
import random
_ = b64decode("Tl5nK8L2KYZRCJCqLF7TbgKLgy1vIkH+KIAJv5/ILFoC+llemcmoLmCQYkiOrJ/orOOV+lwX+cVh+pwE5mtx6w==")
iv = _[:16]
ct = _[16:]



random.setstate(state)

print([_ for _ in zip(x,random.getstate()[1])])

for i in range(ref.size[0] * ref.size[1]-624):
	if i < 300 :
		print(bytes_to_long(random.randbytes(4)[::-1]),random_nums[i+624])
		#print(random_nums.index(bytes_to_long(random.randbytes(4))))
	else:
		z = random.randbytes(4)

print(iv)	
key = bytes(random.sample(random.randbytes(16), 16))
#iv = Random.new().read(AES.block_size)

print(iv,key)


enc = AES.new(key, AES.MODE_CBC, iv)
print(enc.decrypt(ct))
