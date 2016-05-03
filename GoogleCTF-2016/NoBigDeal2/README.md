### No Big Deal 2
>Description: Now for the fun part of this level - can you find the flag in this [pcap](https://github.com/amelkiy/write-ups/releases/download/google_ctf_2016_nbd2/no-big-deal.pcap.gz)  
>250 points  
>I uploaded the gzip version...

It's the same pcap as it was in **No Big Deal 2**. I actually found this flag before the first one because I'm an overkiller... But anyway this is how:  
When we open the pcap the first thing we see is that there is only one TCP stream of an NBD network capture.  
NBD is Network Block Device - meaning that someone is reading from/writing to a block device over the wire.  
So if we look at the protocol we should find something like that:

>Client initiates a connection to the server  
>Handshake between client and server  
>Requests from client to server (read and write)

The handshake consists of some traffic including the magics **NBDMAGIC** and multiple **IHAVEOPT** that are really irrelevant here...
Then there are a couple of requests followed by a couple of replies. The requests being:  
* Read request  
* Wrtie request  
* Disconnect request

We don't really care how we get the data - read or write, the important thing for me was to keep the consistency, that the reads/writes happen in the same order they appear in the capture file.

So the solution seems fairly simple:  
Take the TCP stream without the handshake and follow the requests/reponses when:  
>A request gets saved in a list of requests  
>A response triggers a memory write to a temporary file, when read response writes the data captured from the response and write response writes the data captured from the request.

Each request has a **handle** so it's very simple to match the responses (that hold the handle as well) to the requests they're responding to.  
So I extracted the full TCP stream from the **pcap** file and started parsing it using this technique. Problem is - sometimes in the middle of a big write request there is a response from a previous request and it's impossible to know when you only have the stream without the IP headers...

So then I decided to do another approach - separate the requests from the responses and go over them separately, log all the requests and then go over all the responses, filling the memory accordingly.  
The problem with that was that the random handles were not so random after all...

>0x80f10bbb0088ffff  
>0x60f40bbb0088ffff  
>0x000d1ab10288ffff  
>0xd0051ab10288ffff  
>...

So when I got duplicate handles I decided to do this (pseudo, roughly without error check and stuff):
```python
g_requests = {}
buffer = requests  
last_handle = None
while buffer is not empty:  
  data = buffer.read()
  if data is a request:
    if data.handle in g_requests:
      # Duplicate handle! Switch execution to the responses and fill memory until we
      # complete the previous request with this handle
      buffer.revert_current_read()
      last_handle = data.handle
      buffer = responses  # Read the responses from now on to empty the requests until we can write more
      continue
      
    g_requests[data.handle] = data
  elif data is a response:
    request = g_requests.pop(data.handle)
    fill_memory(request.data if data is WRITE_COMMAND else response.data)
    if handle == last_handle:
      # Now we can return execution to the requests since we cleared the duplicate handle entry
      lst_handle = None
      buffer = requests   # Return execution to the request-reading-flow
```

And thus, manipulating between requests and responses I finally managed to write all the data consistantly to the file.  
So I got a **4GB memory file** (The disk size is **0x100000000** - 2^32 bytes) and the requests sometimes actually write to **0xffffe000**...  
And I check it with `file` and I get that it's a BTRFS filesystem, which is great! `mkdir fs; mount -t btrfs memory.bin fs` and:  
The filesystem is empty...

So i figured either I don't have enough data to really parse the full FS or maybe the client writes files and then deletes them.  
So after issuing a couple of `btrfs check --repair`'s, several BTRFS undelete tools and other stuff I decided to go with the second theory.
So using a BTRFS tool called `btrfs-find-root` I started to check the file after each memory write.  
What I noticed is that the root inode changes each time there is a write to memory address **0x04000000**  
Which makes sense since it's a copy of the superblock in BTRFS.

So what I did is stop the script each time there is a write to **0x04000000** and mount the image. After a couple of writes I finally noticed the actual files being written!  
The client writes to the server **boot** directory with **vmlinuz** and **grub** and everything, and then writes a **lib.tar.gz**  
A quick examination of the two shows that there are 2 rogue files in there:
* /boot/grub/locale/en@straylian.mo  
* /lib.tar.gz/libfancy.so

Both are identical and are XZ-compressed files that contain the flag (one of the included [here](./libfancy.so.txt):  
**CTF{how.did.you.find.this}**

All in all - a good challenge, I overkilled it a little since one the XZs exists in the pcap file and can be extracted with **binwalk**, it's just that my VM was really low on memory and binwalk couldn't run :)

In the directory:
* [The pcap (gzipped)](https://github.com/amelkiy/write-ups/releases/download/google_ctf_2016_nbd2/no-big-deal.pcap.gz)
* [The requests from it](https://github.com/amelkiy/write-ups/releases/download/google_ctf_2016_nbd2/nbd_requests.bin)
* [The responses from it](https://github.com/amelkiy/write-ups/releases/download/google_ctf_2016_nbd2/nbd_responses.bin)
* [The script that does all the work](./nbd.py)
* [The snapshot of the memory with the files](https://github.com/amelkiy/write-ups/releases/download/google_ctf_2016_nbd2/memory.bin.gz) - Careful, this expands to 4GB
* [The file with the flag](./libfancy.so.txt)

