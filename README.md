# DNS Message Parser

This is a solution to an interview problem I got from cloudflare. Given a byte string, decode it into DNS Message. Meant to complete the challenge in 7 days. DNS message looks something like this below:

```bash
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 6185
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;google.com.			IN	A

;; ANSWER SECTION:
google.com.		127	IN	A	142.250.217.174

;; Query time: 13 msec
;; SERVER: 2600:1700:4c0c:e000::1#53(2600:1700:4c0c:e000::1)
;; WHEN: Sun Oct 22 21:18:46 EDT 2023
;; MSG SIZE  rcvd: 55
```

Resources I found 

https://docstore.mik.ua/orelly/networking_2ndEd/dns/appa_02.htm
