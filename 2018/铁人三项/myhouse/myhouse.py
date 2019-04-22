from pwn import *
from change_ld import *

context.log_level = "debug"
context.terminal = ["terminator","-e"]

bin = change_ld("myhouse","ld-2.23.so")
libc = ELF("libc_64.so")
p = bin.process()

def Debug():
    gdb.attach(p)

def began(own,name,size,descrip):
p.sendlineafter("What's your name?\n",own)
p.sendlineafter("house?\n",name)
p.sendlineafter("house?\n",str(size))
p.sendlineafter("description?\n",descrip)

def Built(size):
    p.sendlineafter("Your choice:\n","1")
    p.sendlineafter("room?\n",str(size))

def Decorate(data):
    p.sendlineafter("Your choice:\n","2")
    p.sendlineafter("shining!\n",date)

def View():
    p.sendlineafter("Your choice:\n","2")

began("")
