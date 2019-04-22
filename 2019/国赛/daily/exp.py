from pwn import *

bin = ELF("pwn")
p = bin.process()

def Debug():
    gdb.attach(p)
    pause()

def add(size,content):
    p.sendlineafter("choice:","2")
    p.sendlineafter("daily:",str(size))
    p.sendlineafter("daily\n",content)

def delete(idx):
    p.sendlineafter("choice:","4")
    p.sendlineafter("daily:",str(idx))

def edit(idx,content):
    p.sendlineafter("choice:","3")
    p.sendlineafter("daily:",str(idx))
    p.sendlineafter("daily:",content)

def edit(idx):
    p.sendlineafter("choice:","1")
    
add(0x20,"A"*0x10)
add(0x20,"A"*0x10)
Debug()