# WhisperDNS — Writeup

**Category:** Forensics / Network / DNS Covert Channel
**Points:** 450
**Difficulty:** Hard
**Flag:** `cyberstrike{dns_tunn3l_l4b3ls_r34ss3mbl3d}`

## Challenge Description

> After the LeakyStream incident, NovaTek blocked outbound HTTP to unknown
> hosts. The intruder adapted. The next capture looks almost entirely like
> ordinary name resolution — but data still left the network, one whisper
> at a time.
>
> DNS was never meant to carry payloads. That has never stopped anyone.
> Find the queries that aren't really asking a question, put them back in
> order, and decode what they were spelling out.

## Setup

No packet-analysis tooling (`tshark`/`tcpdump`/`scapy`/`dpkt`) or network
access was available in the environment, so the pcap was parsed from
scratch in pure Python: a small pcap-global/record-header reader, then an
Ethernet → IPv4 → UDP → DNS message parser (with DNS name-compression
pointer support), enough to dump every query/response pair.

```
$ file whisperdns.pcap
whisperdns.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet)
```

47 packets total, all IPv4/UDP port 53 (DNS) between `192.168.1.50`
(client) and `192.168.1.1` (resolver).

## Finding the Covert Channel

Dumping every query/response side by side shows two distinct populations:

- **Normal-looking lookups** (`www.example.com`, `fonts.gstatic.example`,
  `ntp.pool.example`, `api.weather.example`, `cdn.jsdelivr.example`,
  `mail.novatek.example`, `update.novatek.example`, …) — each of these
  always gets an `A` record response.
- **A second set of queries** for names like
  `seq00.mn4wezls.tunnel.exfil-c2.example` — these **never get a
  response** anywhere in the capture. They exist purely as outbound
  queries; the "answer" was never the point, the *question itself* was the
  payload. This is the classic shape of a DNS-tunneled exfil channel: data
  is smuggled out in the subdomain labels of queries the attacker's
  resolver is authoritative for, and no meaningful response is needed
  because the channel is one-way (client → attacker-controlled resolver).

Extracting every query under `*.tunnel.exfil-c2.example` gives exactly 9
entries, each of the form `seqNN.<data-label>.tunnel.exfil-c2.example`:

```
seq00.mn4wezls.tunnel.exfil-c2.example
seq01.on2he2ll.tunnel.exfil-c2.example
seq02.mv5wi3tt.tunnel.exfil-c2.example
seq03.l52hk3to.tunnel.exfil-c2.example
seq04.gnwf63bu.tunnel.exfil-c2.example
seq05.mizwy427.tunnel.exfil-c2.example
seq06.oizti43t.tunnel.exfil-c2.example
seq07.gnwwe3bt.tunnel.exfil-c2.example
seq08.mr6q.tunnel.exfil-c2.example
```

The `seqNN` prefix is the reassembly hint from the challenge description
("put them back in order") — the exfil queries are interleaved with
ordinary background traffic in the capture (to blend in / evade naive
"every DNS query looks the same" detection), so the capture order isn't
the payload order; the explicit sequence number is.

## Decoding

The data labels use only lowercase letters and the digits `2`–`7` — exactly
the character set of **lowercase RFC 4648 Base32** (`a-z2-7`), which is a
DNS-label-safe encoding (case-insensitive, no `+`, `/`, or `=` mid-string)
commonly used by real DNS-tunneling tools (iodine, dnscat2, etc.) for
exactly this reason.

Sorting by `seqNN`, concatenating the data labels, upper-casing, and
padding to a multiple of 8 characters with `=` for standard Base32
decoding:

```python
seqs = {0:'mn4wezls', 1:'on2he2ll', 2:'mv5wi3tt', 3:'l52hk3to', 4:'gnwf63bu',
        5:'mizwy427', 6:'oizti43t', 7:'gnwwe3bt', 8:'mr6q'}
combined = ''.join(seqs[k] for k in sorted(seqs))
# 'mn4wezlson2he2llmv5wi3ttl52hk3tognwf63bumizwy427oizti43tgnwwe3btmr6q'

import base64
s = combined.upper()
s += '=' * ((-len(s)) % 8)
print(base64.b32decode(s).decode())
```

```
cyberstrike{dns_tunn3l_l4b3ls_r34ss3mbl3d}
```

The decode succeeds cleanly with no leftover garbage bytes, confirming
both the correct alphabet and the correct sequence ordering.

## Flag

```
cyberstrike{dns_tunn3l_l4b3ls_r34ss3mbl3d}
```

## Takeaways

- **Queries with no matching response are the tell.** In a legitimate
  resolution flow every query gets an answer; a one-way exfil channel
  riding on DNS queries doesn't need one, so filtering for
  query-without-response is a fast way to separate "real" DNS traffic from
  a tunnel, even before looking at the label content.
- **Interleaving covert queries with realistic decoy traffic** (repeated
  legitimate-looking lookups to CDN/NTP/mail/update hostnames) is a common
  evasion technique — an explicit in-band sequence number
  (`seqNN`) is what lets a defender (or a solver) reconstruct the true
  order regardless of capture/interleave order.
- **`a-z2-7` in a hostname label is a strong signal of Base32** — it's the
  standard DNS-tunneling encoding of choice specifically because it's
  case-insensitive and uses only characters valid in DNS labels, unlike
  Base64.
