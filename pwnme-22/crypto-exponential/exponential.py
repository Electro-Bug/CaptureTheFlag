from pwn import *
from Crypto.Util.number import *

"""
You can have the result of whatever operation between multiplication, exponentiation, addition, division and substraction !
Also you can choose the value with which you can apply the operation. You have only 64 attempts to retrieve the flag.

a = 11070000470311244362307674108773743459030761741263836109464755698171103189755419619315982123943233108331537286993037858487084163785833931758083259849770029
x = ?
n = 9366552427487235284323626664050708742836749948595054285433124544079421653694620446849771439855662852170325198465221599526022298082356027278220058901616237
(a**x) % n = 3464158571721202429990852445689725011435671689801850617451314721792313413373013744379831630994457270176211374159483358473128738132320327813188656680244232 

[+] Give me the operation you want to make and I'll give you the result : /
[+] Give me the value of the number after your operation : 115792089237316195423570985008687907853269984665640564039457584007913129639936
Result : 1921745621582887002195691469433055847980124132179386963485053470494656482044907223369707273836859915111091613573185015772186677883876310119827527628526320 
"""

io = remote("pwn.pwnme.fr",7003)

# Receive a
io.recvuntil(b"a = ")
a = int(io.recvline().strip())
# Receive n
io.recvuntil(b"n = ")
n = int(io.recvline().strip())

print(a,n)

# Mapping
def do_maps(k,n):
	maps = {}
	for i in range(256):
		_ = pow(a,k+i,n)
		maps[str(_)]=i
	return maps
	
# do ops
def divide(io,n,maps):
	io.recvuntil(b"[+] Give me the operation you want to make and I'll give you the result :")
	io.sendline(b"/")
	io.recvuntil(b"[+] Give me the value of the number after your operation :")
	io.sendline(str(2**(8*n)).encode())
	io.recvuntil(b"Result : ")
	res = io.recvline().strip()
	print(i,res)
	if res.decode() in maps.keys() and i>0:
		print("Found",n, chr(maps[res.decode()]))
		return maps[res.decode()]
	res = -1

flag = 0
for i in range(38,-1,-1):
	maps = do_maps(flag,n)
	res = divide(io,i,maps)
	print(res)
	flag+=res
	flag*=256
	print(long_to_bytes(flag))
	#input()
	
	