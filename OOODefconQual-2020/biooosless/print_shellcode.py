shellcode = file('shellcode.bin', 'rb').read()
print hex(len(shellcode))
print shellcode.encode("base64").replace("\r", "").replace("\n", "")
