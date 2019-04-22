from pwn import *
context.log_level = "debug"

p = remote("39.97.228.196",10001)
p.sendlineafter("name:","badrer12")
p.sendafter("word:","xyz{|}")
p.recvall()