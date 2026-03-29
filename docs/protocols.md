# Supported Protocols

NetTrap emulates 26 network protocols:

## Tier 1 — Core Protocols
| Protocol | Port | Listener Name | Use Case |
|----------|------|--------------|----------|
| DNS | 53 | `dns` | Domain resolution honeypot |
| HTTP/HTTPS | 80/443 | `http`/`https` | Web server honeypot |
| SMTP | 25 | `smtp` | Email server honeypot |
| FTP | 21 | `ftp` | File server honeypot |
| SSH | 22 | `ssh` | SSH brute-force capture |
| Telnet | 23 | `telnet` | IoT malware capture (Mirai) |
| POP3 | 110 | `pop3` | Email client honeypot |
| IRC | 6667 | `irc` | Bot C2 capture |
| TFTP | 69 | `tftp` | Firmware/payload capture |

## Tier 2 — Enterprise/Cloud Protocols
| Protocol | Port | Listener Name | Use Case |
|----------|------|--------------|----------|
| SMB | 445 | `smb` | Ransomware lateral movement |
| RDP | 3389 | `rdp` | Ransomware initial access |
| Redis | 6379 | `redis` | Cloud exploitation |
| MySQL | 3306 | `mysql` | Database exploitation |
| LDAP | 389 | `ldap` | AD attacks, Log4Shell |
| MQTT | 1883 | `mqtt` | IoT C2 |
| PostgreSQL | 5432 | `postgres` | Database exploitation |

## Tier 3 — Specialized Protocols
| Protocol | Port | Listener Name | Use Case |
|----------|------|--------------|----------|
| SNMP | 161 | `snmp` | Network recon |
| SOCKS | 1080 | `socks` | Proxy malware |
| Memcached | 11211 | `memcached` | DDoS amplification |
| SIP | 5060 | `sip` | VoIP fraud |
| UPnP/SSDP | 1900 | `upnp` | IoT discovery |
| NTP | 123 | `ntp` | Amplification attacks |
| CoAP | 5683 | `coap` | IoT constrained devices |
| NKN | 30001 | `nkn` | NKAbuse malware |
| QUIC | 443 | `quic` | HTTP/3 detection |
| Raw | any | `raw` | Catch-all handler |

## Protocol Detection

NetTrap uses a taste-based scoring system to auto-detect protocols:
- Each protocol has a taste detector with confidence scoring (0-100)
- Port-based hints boost confidence
- Content-based detection for protocol magic bytes
- Highest-scoring protocol wins

Any protocol can run on any port. The taste router detects by content, not just port number.
