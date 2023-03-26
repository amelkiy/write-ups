#!/usr/bin/env python3
from flask import Flask, send_from_directory, render_template, session, request, Response
from secrets import token_hex
from dnslib import DNSRecord, QTYPE, RR, A
from base64 import urlsafe_b64decode
import os
import requests
import requests_doh
from redis import Redis

"""
Docker image:
python:3.11

Dependencies:
Flask==2.2.3
dnslib==0.9.23
requests==2.28.2
requests-doh==0.3.0
redis==4.5.1
gunicorn==20.1.0
"""

FLAG = os.getenv("FLAG", "INS{fake_flag}")
DOMAIN = os.getenv("DOMAIN", "sleepsafedoh.insomnihack.ch")
CHALLENGE_DOMAIN = "insomnihack.flag"

RESOLVER = os.getenv("RESOLVER", "https://dns.google/dns-query")
REQ_TEMPLATE = requests.Request("POST", RESOLVER, headers={
    "Content-Type": "application/dns-message",
    "Accept": "application/dns-message"
}).prepare()


app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "asdkjfhakljsdfhalkdjsfh")
assert app.secret_key is not None

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

redis = Redis(host="redis", port=6379, db=0)

requests_doh.add_dns_provider("sleepsafedoh", f"https://{DOMAIN}/dns-query")
requests_doh.set_dns_cache_expire_time(1)

@app.route("/", methods=["GET"])
def index():
    if "subdomain" not in session:
        session["subdomain"] = token_hex(8)
    challenge_host = session["subdomain"] + "." + CHALLENGE_DOMAIN
    return render_template("index.html", challenge_host=challenge_host, domain=DOMAIN)

@app.route("/static/<path:path>", methods=["GET"])
def static_file(path):
    return send_from_directory("static", path)

@app.route("/source", methods=["GET"])
def source():
    return send_from_directory(".", "app.py")

@app.route("/dns-query", methods=["GET"], defaults={"dns": None})
def dns_query_get(dns):
    if dns is None:
        return "Invalid request", 400
    
    query = urlsafe_b64decode(dns)
    return Response(process_dns_query(query), mimetype="application/dns-message")

@app.route("/dns-query", methods=["POST"])
def dns_query_post():
    return Response(process_dns_query(request.data), mimetype="application/dns-message")

@app.route("/send-flag", methods=["POST"])
def send_flag():
    if "subdomain" not in session:
        return "Invalid session", 400
    
    port = 80
    if "port" in request.args:
        try:
            port = int(request.args["port"])
        except:
            return "Invalid port", 400
    
    if port < 1 or port > 65535:
        return "Invalid port", 400
    
    host = session["subdomain"] + "." + CHALLENGE_DOMAIN
    try:
        s = requests_doh.DNSOverHTTPSSession(provider="sleepsafedoh")
        s.post(f"http://{host}:{port}", data=FLAG, timeout=1)
    except requests_doh.exceptions.DNSQueryFailed as e:
        return str(e)
    except:
        return "Error"

    return f"Flag sent to {host}"

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


if __name__ == "__main__":
    app.run()
