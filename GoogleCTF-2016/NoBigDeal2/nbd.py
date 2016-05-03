from StringIO import StringIO
from struct import unpack

# The file that will hold the actual memory
g_memory = file('memory.bin', 'wb')
for i in xrange(0, 0x100000000, 1024*1024*100):
    # Fill it with \0s first to be able to "seek" inside it when needed
    g_memory.write('\0' * 1024*1024*100)
g_memory.write('\0' * 2)    # Need to write actually just one more byte because we write to 0x100000000 but...


def fill_mem(offset, my_data):
    g_memory.seek(offset, 0)
    g_memory.write(my_data)
    g_memory.flush()

g_requests = {}

REQUEST_MAGIC = "25609513".decode("hex")
RESPONSE_MAGIC = "67446698".decode("hex")

READ_CMD = 0
WRITE_CMD = 1
DISC_CMD = 2


def read_convo():
    reqs = file('nbd_requests.bin', 'rb').read()
    resps = file('nbd_responses.bin', 'rb').read()

    reqs_ss = StringIO(reqs)
    resps_ss = StringIO(resps)
    last_handle = None
    while True:
        if not last_handle:
            buf = reqs_ss
        else:
            buf = resps_ss

        cmd = buf.read(4)
        if cmd == REQUEST_MAGIC:
            header = buf.read(24)
            flags, type_, handle, offset, length = unpack(">HH8sQI", header)

            if type_ == WRITE_CMD:
                data = buf.read(length)
            elif type_ == READ_CMD:
                data = ''
            elif type_ == DISC_CMD:
                last_handle = True  # Just to go over the remaining responses
                continue
            else:
                print 'ERROR unknown type request %s (%08x)!' % (handle.encode("Hex"), type_), hex(buf.tell())
                return False

            if handle in g_requests:
                # Switch execution to <responses> to empty the requests dict so we can then add this duplicate entry
                last_handle = handle
                buf.seek(-(4 + 24 + len(data)), 1)  # Seek back since we need to read this when execution is returned to us
                continue

            g_requests[handle] = (type_, offset, length, data)
        elif cmd == RESPONSE_MAGIC:
            header = buf.read(4+8)
            flags, error, handle = unpack(">HH8s", header)
            if handle not in g_requests:
                print 'ERROR no handle %s in requests!' % handle.encode("Hex"), hex(buf.tell())
                return False
            if error != 0:
                print 'ERROR error %08x in request %s!' % (error, handle.encode("Hex")), hex(buf.tell())
                return False
            (type_, offset, length, req_data) = g_requests.pop(handle)
            if type_ == READ_CMD:
                data = buf.read(length)
            elif type_ == WRITE_CMD:
                data = req_data
            else:
                print 'ERROR unknown type %s (%08x) in requests!' % (handle.encode("Hex"), type_), hex(buf.tell())
                return False

            assert len(data) == length

            # No need to write all 0s, just messes up things. We don't really want to delete data and we don't really delete any blocks/superblocks
            if data.count('\0') != len(data):
                if type_ == READ_CMD:
                    print 'Filling memory from read - offset %08x to %08x (%08x bytes)' % (offset, offset + len(data), len(data))
                elif type_ == WRITE_CMD:
                    print 'Filling memory from write - offset %08x to %08x (%08x bytes)' % (offset, offset + len(data), len(data))
                fill_mem(offset, data)
                if offset == 0x04000000:
                    print 'Try now!'
                    raw_input()

            if handle == last_handle:
                # Return execution to the requests - we cleared the duplicate request entry!
                last_handle = None
        elif cmd == '':
            if buf == resps_ss:
                return True
            else:
                # Finished with requests! Now just go on to the responses until there are no more
                last_handle = True
        else:
            print 'ERROR unknown cmd %s' % cmd.encode("hex"), hex(buf.tell())
            return False

read_convo()

g_memory.close()

assert len(g_requests) == 0

print 'Done!'
