import sys
import struct
import gzip

d = [
    'right',
    'left',
    'up',
    'down',
    'A',
    'B',
    'start',
    'select',
]

res = ''
s = file(sys.argv[1], 'rb').read()
for line in s.splitlines():
    if '#' in line:
        line = line.split('#')[0]

    line = line.strip()
    if line == '':
        continue
    
    is_full_key = False
    if '*' in line:
        cmd, num = line.split('*')
        if '!' in num:
            num = num.replace('!', '')
            is_full_key = True
        num = float(num)
    else:
        cmd = line
        num = 1
    
    b = [0]*8
    if cmd == 'INIT':
        cmd = 'None'
        num = 358
    elif cmd.startswith('ENDLEVEL'):
        num = 47
        if '-' in cmd:
            minus = int(cmd.split('-')[1])
            num -= minus

        cmd = 'None'
    elif cmd == 'END':
        cmd = 'None'
        num = 10000
        
    if cmd != 'None':
        b[d.index(cmd)] = 1
        num = num*11
    
    num = int(num)
    b = ''.join([chr(x) for x in b])
    if is_full_key:
        res += b*num
    else:
        res += (b * (num-11)) + b + ('\0'*8*10)

res = struct.pack("<Q", len(res)/8) + res
gzip.GzipFile(sys.argv[1] + '.bin', "w").write(res)
