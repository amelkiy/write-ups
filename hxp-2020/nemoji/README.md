# hxp 2020 - nemoji
## Overview
This challenge was made by taking the binary from the `no-eeeeeeeeeeeemoji` challenge from Dragon CTF 2020 and patching some places in the binary. I suggest reading the AWESOME [Write Up of the original challenge by r3billions](https://r3billions.com/writeup-no-eeeeeeeeeeeemoji/) first, so that you have a sense of what's happening in the binary.  
The patches made to the binary are:  
* It does not print `/proc/maps` anymore, so we don't know where **[vdso]** is
* It does not apply the `% 1000` manipulation to the `rand()`, so that the random value could be any number
* It does not make sure that the allocated page is under 0x10000 - note that mmap() will fail in that case!
* It does not perform the sys_write syscall before exiting

I was working with my friend [@nivye](https://github.com/nivye), who brought a significant reinforcement since he worked on the original challenge in Dragon CTF.  

## Finding the Right Opcode
So this whole challenge is based on one thing - find the right opcode(s) to execute when your shellcode is ran. You have 2 bytes - good luck. We can't use the **[vdso]** trick now, so we have to think differently. We also need to take into account that we are mapped to high address pages now.  
@nivye prepared a full list of the possible opcodes we could run:  
```
from itertools import product
from pwn import disasm
f = open('all_poissible_opcodes.txt', 'w')
for opcode in product(range(256), repeat=2):
	bin1, bin2 = opcode
	out = f'bin1: {bin1:02x}, bin2: {bin2:02x}\n'
	out += disasm(bytes([bin1, bin2, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]), arch='amd64', vma=0xa0a0a200)
	out += '\n'
	f.write(out)
f.close()
```
Notice the `vma` - it tells the disasm to assume the code is loaded at the address - assuming the page we allocated was at `0xa0a0a000`. This was added for better vieweing different opcodes such as `call   QWORD PTR [rip+0xffffffff90909090]    # 0x31313298` so disasm shows the destination address in a prettier way.  
Actually, to be fair, first we didn't have enough `0x90`s so we didn't see all the available opcodes... Took as too long to spot it and fix it, but eventually we did 😁  
We scrolled through the opcodes for hours, searching for **the one** but each time we would find something, we would see that something wouldn't allow us to use it... For example:  
```
a0a0a200:   ff 25 90 90 90 90       jmp    QWORD PTR [rip+0xffffffff90909090]        # 0x31313298
```
If we manage to allocate 2 maps with a differnece of `0x90909000`, we would execute from the higher map, when the lower map is all 0s, so this opcode will jump to address `0`. That is great, but we can't mmap to 0...  
After a long search, we finally found something... I have to say, I don't think this is how we were intended to solve this challenge, but it's a cool solution anyway :)  

## 64bit -> 32bit -> Luck
The solution that we found is consists of 2 opcodes:  
```
a0a0a200:   98                      cwde   
a0a0a201:   ff 90 90 90 90 90       call   QWORD PTR [rax-0x6f6f6f70] 
```
When we are being ran `eax` contains `0xdeafbeefdeadbeef`. The [CWDE](http://www.cwde.de/) *(WTF it has its own website??)* opcode sign-extends `AX` to `EAX`. In reality, it does a little something extra - it 0s out the high 32 bit of `RAX`, so after the opcode runs: `RAX = 0x00000000ffffbeef`.  
The second opcode takes the QWORD stored in `[rax-0x6f6f6f70] = 0x90904f7f` and jumps there. This is kinda cool. If we manage to mmap ourselves to `0x90904000`, then we control the `0x7f7` offset!  
All we would need to do then is put `0x0000000090904000` in that offset and the code will jump to the beginning of our payload - there we can `asm(shellcraft.amd64.sh(), arch='amd64'))` and win.  
Taking the relevant parts directly from r3billions's Write Up, this is the revised payload part:  
```
payload = str(asm(shellcraft.amd64.sh(), arch='amd64'))
payload += '\x90' * (512 - len(payload))
payload += '\x98\xff'
payload += '\x90' * (0xf7f - len(payload))
payload += '\x00\x40\x90\x90\x00\x00\x00\x00'
payload += '\x90' * (4096 - len(payload))
```
But... We have to wait for rand() to return 0x90904...

## Brute Force vs. Prediction
Fortunately, the program doesn't do much with the random except `srand(NULL)` and `rand()` - so we can actually predict all of the pages that will get mapped, for each second that we connect to the server. We need to take into account 2 issues:  
* Timing - we are limited to 5 minutes, so we only get a couple of thousands of tried per conenction (3800 tries measured on my computer against the real server)
* Small values of rand() - if by any chance rand() will return a value under 16, the program will crash  

So we need to brute force `srand(timestamp)` with 3800 tries and make sure that we don't get a small value.  
Our prediction script predicted that we would get `0x90904` if we connect to the server at exactly `Sun Dec 20 04:42:38 2020 GMT`, which is `seed = 1608439358` and iterate 785 times.  

## Flag
With all that said, @nivye was more adventerous than me and just ran the script with multiple instances. He got the flag in a couple of minutes 😁  
![Flag!](https://github.com/amelkiy/write-ups/blob/master/hxp-2020/nemoji/flag.png?raw=true)
To this day I don't know why the random prediction was wrong, but fraknly, it saved us from staying up until 6:42 am (Israel time) so.. Thanks @nivye! 😜  
