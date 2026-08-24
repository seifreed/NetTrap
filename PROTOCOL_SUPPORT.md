# Protocol Support

NetTrap registers 35 content/port detectors. Detector presence does not mean a
complete protocol implementation. The alpha focuses on identifying traffic,
recording behavior, and returning enough synthetic protocol data for controlled
malware-analysis labs.

`Client E2E` means a required CI path uses an external client against a running
NetTrap process. Crate unit/integration tests exist beyond the entries marked
Yes, but they do not establish real-client compatibility.

The required client contract is `dig` 9.x, `curl` 8.x, OpenSSL 3.x or
LibreSSL 3.x, plus `ldapsearch` when installed. `tests/verify_platform.sh`
fails on other required-client major versions and logs the exact client
versions used by each runner. The release Docker smoke also runs `ldapsearch`,
`redis-cli`, `mosquitto_pub`, and curl's POP3/IMAP clients. LDAP is skipped with
an explicit warning on host runners when the optional client is unavailable. A
new major is added only after the same E2E suite passes with it.

| Handler | Current behavior | Client E2E | Known ceiling |
|---|---|---:|---|
| DNS | Parses UDP/TCP queries and builds synthetic records/NXDOMAIN responses | Yes (`dig`, UDP and TCP) | Broad resolver compatibility is not a required gate |
| HTTP | Parses requests, records metadata/body length, serves default/custom/webroot responses | Yes (`curl`, HTTP and HTTPS) | Not a production web server; browser compatibility is not a required gate |
| TLS | Detects ClientHello, fingerprints it, and can terminate inbound TLS locally | Yes (`openssl s_client`) | No general upstream MITM, selective passthrough, or pinning bypass |
| SMTP | Stateful command handling and DATA capture | Yes (`curl`) | Synthetic server; no delivery or broad mail-client compatibility gate |
| FTP | Stateful command handling, passive transfers, and configured file serving | Yes (`curl`, EPSV/RETR) | Synthetic file set; no broad FTP-client compatibility gate |
| POP3 | USER/PASS and mailbox-command emulation | Yes (curl POP3) | Synthetic mailbox only |
| IRC | Registration/channel command emulation and logging | No | Partial IRC session behavior |
| IMAP/IMAPS | Explicit listener banner and command subset | Yes (curl IMAP auth probe) | No content detector; must be selected by listener name |
| TFTP | RRQ/WRQ block handling and configured file root | No | No required real-client transfer E2E |
| Telnet | Negotiation/prompt responses and command capture | No | Port-open smoke only; not a full terminal server |
| SSH | Banner and partial KEX/authentication responses | No | Does not complete a normal OpenSSH authentication session |
| SMB | SMB1/SMB2 parsing and synthetic negotiation | No | Fixed partial SMB2 behavior; not full SMB2/SMB3 file sharing |
| RDP | X.224/Cookie parsing and synthetic negotiation data | No | No complete RDP security or desktop session |
| Redis | RESP parsing and a command-response subset | Yes (`redis-cli`, PING) | No persistence, replication, or full Redis semantics |
| MySQL | Handshake, login metadata, STARTTLS handling, and query parsing | No | No SQL engine or required client compatibility gate |
| PostgreSQL | Startup/auth/query subset | No | No SQL engine or required client compatibility gate |
| LDAP | BER message parsing and bind/search response subset | Yes (`ldapsearch`, when installed) | Not an Active Directory implementation |
| MQTT | Packet parsing and CONNECT/PUBLISH/SUBSCRIBE response subset | Yes (`mosquitto_pub`) | Not a complete broker |
| SNMP | BER request parsing and synthetic responses | No | Limited operations/MIB behavior |
| SOCKS | SOCKS4/5 handshake and CONNECT logging | No | Does not provide a general upstream proxy |
| Memcached | Text/binary command parsing and synthetic responses | No | No complete cache semantics |
| NKN | JSON-RPC response subset and binary header detection | No | Not an NKN peer/node implementation |
| SIP | Request-line/header parsing and synthetic responses | No | No RTP/media or complete transaction state |
| UPnP/SSDP | Discovery/control request parsing and synthetic responses | No | No real device or persistent port mapping |
| NTP | Request detection and synthetic server response | No | Limited packet modes; no clock service guarantees |
| CoAP | Message parsing and simple ACK/response behavior | No | No complete resource server/observe support |
| QUIC | Long-header/version signal detection | No | No QUIC decryption, handshake, or HTTP/3 implementation |
| Finger | Query logging and simple response | No | Minimal one-request emulation |
| Ident | RFC 1413-style query/response | No | Minimal one-request emulation |
| Daytime | RFC 867-style response | No | One-shot diagnostic response |
| Time | RFC 868-style response | No | One-shot diagnostic response |
| Chargen | Bounded synthetic character response | No | One-shot diagnostic response |
| QOTD | Synthetic quote response | No | One-shot diagnostic response |
| Syslog | Inbound message parsing/capture | No | Capture only; not a syslog relay or durable server |
| Raw | Configured echo/static/base64/file/silent fallback modes | No | No protocol semantics |
| Dummy | Internal fallback detector/handler | No | Internal testing/fallback behavior, not a public protocol |

## TLS Terminology

`use_ssl = true` wraps a configured local listener in TLS and passes decrypted
bytes to that local handler. It does not connect to the original upstream
server. Documentation and release notes therefore call this local TLS
termination, not full transparent TLS MITM.
