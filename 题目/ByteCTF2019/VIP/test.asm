A = arch
A == ARCH_X86_64 ? next : dead
A = sys_number
A == execve ? dead : ok
ok:
return ALLOW
dead:
return ERRNO(0)

