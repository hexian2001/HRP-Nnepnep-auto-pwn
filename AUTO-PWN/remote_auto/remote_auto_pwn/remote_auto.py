# encoding=utf-8
from pwn import *
import sys
import os

context(log_level='debug', arch='amd64')
r = remote(sys.argv[1], sys.argv[2])
data = base64.b64decode(r.recvline(timeout=5).decode("ASCII"))
# r.sendline('execute')
open("remote_pwn", "wb").write(data)
os.system("python3 HRP-FUZZ-2.0.py ./remote_pwn auto remote ")
elf = ELF('remote_pwn')
libc = elf.libc
# 读取文本文件，每一行作为代码片段执行，并保存变量
code_dict = {}
with open('output.txt', 'r') as f:
    for line in f:
        line = line.strip()
        if line:
            exec(line, globals(), code_dict)
