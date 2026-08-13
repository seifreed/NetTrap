# Supported Protocols

NetTrap registers 35 protocol detectors: 33 runtime service/fallback handlers,
plus the TLS and internal Dummy detectors. The tables below list the 33 handlers
that can be selected as listener services.

## Tier 1: Core Protocols

| Protocol | Port | Listener Name | Use Case |
|----------|------|---------------|----------|
| DNS | 53 | `dns` | Domain resolution honeypot |
| HTTP/HTTPS | 80/443 | `http`/`https` | Web server honeypot |
| SMTP | 25 | `smtp` | Email server honeypot |
| FTP | 21 | `ftp` | File server honeypot |
| SSH | 22 | `ssh` | SSH brute-force capture |
| Telnet | 23 | `telnet` | IoT malware capture |
| POP3 | 110 | `pop3` | Email client honeypot |
| IRC | 6667 | `irc` | Bot C2 capture |
| TFTP | 69 | `tftp` | Firmware and payload capture |

## Tier 2: Enterprise and Cloud

| Protocol | Port | Listener Name | Use Case |
|----------|------|---------------|----------|
| SMB | 445 | `smb` | Ransomware lateral movement |
| RDP | 3389 | `rdp` | Ransomware initial access |
| Redis | 6379 | `redis` | Cloud exploitation |
| MySQL | 3306 | `mysql` | Database exploitation |
| LDAP | 389 | `ldap` | AD attacks and Log4Shell capture |
| PostgreSQL | 5432 | `postgres` | Database exploitation |
| MQTT | 1883 | `mqtt` | IoT C2 |
| SOCKS | 1080 | `socks` | Proxy malware detection |
| Memcached | 11211 | `memcached` | DDoS amplification and data theft |

## Tier 3: Specialized

| Protocol | Port | Listener Name | Use Case |
|----------|------|---------------|----------|
| SNMP | 161 | `snmp` | Network reconnaissance |
| SIP | 5060 | `sip` | VoIP fraud detection |
| UPnP/SSDP | 1900 | `upnp` | IoT discovery and port mapping |
| NTP | 123 | `ntp` | Amplification detection |
| CoAP | 5683 | `coap` | Constrained IoT devices |
| NKN | 30001 | `nkn` | NKN protocol and P2P detection |
| QUIC | 443 | `quic` | HTTP/3 detection |
| Raw | any | `raw` | Catch-all response handler |

## Tier 4: Legacy and Diagnostic

| Protocol | Port | Listener Name | Use Case |
|----------|------|---------------|----------|
| Finger | 79 | `finger` | User enumeration reconnaissance |
| Ident | 113 | `ident` | RFC 1413 identity lookup |
| Daytime | 13 | `daytime` | RFC 867 diagnostic response |
| Time | 37 | `time` | RFC 868 timestamp response |
| Chargen | 19 | `chargen` | RFC 864 amplification bait |
| QOTD | 17 | `quotd` | RFC 865 quote-of-the-day response |
| Syslog | 514 | `syslogrecv` | RFC 3164/5424 message capture |

## Protocol Detection

NetTrap uses taste-based scoring to auto-detect protocols:

- Each detector assigns a confidence score from 0 to 100.
- Port-based hints boost confidence.
- Content-based detection recognizes protocol magic bytes and framing.
- The highest-scoring detector wins.

Any handler can run on any port. The router detects by content, not only by the
destination port.
