# remcos-rat-network-analysis
Screenshot-based investigation of a Remcos RAT-labeled packet capture using Wireshark, VirusTotal, and AbuseIPDB, with evidence-based findings and tentative MITRE ATT&amp;CK mapping.

# Malware Analysis: Remcos RAT Network Traffic Investigation & MITRE ATT&CK Mapping

**Author:** [Dhlalambi Clive]
**Report preparation date:** [28 June 2026]
**Capture filename:** 2024-09-11-Remcos-RAT-infection-traffic.pcap
**Scope:** Screenshot-based network traffic investigation

## 1. Executive Summary

This project examines screenshots of a packet capture labeled as Remcos RAT
infection traffic.

The visible Wireshark evidence shows a DNS lookup for
`eadzagba1[.]duckdns[.]org`, resolving to `198[.]46[.]178[.]133`.
The internal host subsequently establishes a TCP connection to that address
on destination port 4877, followed by traffic identified by Wireshark as TLS 1.3.

A separate DNS lookup resolves `geoplugin[.]net` to `178[.]237[.]33[.]50`.

The supplied VirusTotal screenshot reports that 10 of 92 vendors flagged
the URL `hxxp://178[.]237[.]33[.]50/`. The AbuseIPDB screenshots show
255 historical reports alongside a displayed abuse confidence score of 0%.

These reputation results provide context but do not prove that the
geoplugin service or its IP address acted as malware command-and-control
infrastructure in this capture.

The Remcos label comes from the capture filename; malware-family attribution
has not been independently verified in this screenshot-only analysis.

## 2. Evidence and Scope

### Evidence reviewed

- Wireshark traffic overview.
- Wireshark DNS response details.
- VirusTotal URL search and results screenshots.
- AbuseIPDB overview and historical report screenshots.

### Scope limitations

The original PCAP and malware executable were not supplied for direct analysis.
Findings are limited to what is visible in the screenshots.

The Wireshark status bar displays 80 packets, but the screenshots do not
show all packet contents.

The date September 11, 2024 appears in the capture filename.
The screenshot desktop clock displays June 28, 2026.
Neither is independently verified as the actual packet acquisition date.

Reputation results are recorded as historical screenshot observations,
not as current or capture-time verdicts.

## 3. Analysis Workflow Documented by the Screenshots

1. Inspect the traffic overview in Wireshark.
2. Identify the internal host and DNS resolver.
3. Review DNS queries and responses.
4. Identify the connection following the DuckDNS resolution.
5. Record the destination address, destination port, and displayed protocol.
6. Review the geoplugin DNS response.
7. Compare the supplied VirusTotal and AbuseIPDB reputation results.
8. Separate directly observed facts from behavioral hypotheses.
9. Consider tentative MITRE ATT&CK mappings.

## 4. Network Findings

### 4.1 Internal host and DNS resolver

The screenshots show:

- Internal host: `10.9.11.101`
- DNS resolver: `10.9.11.1`

These are observed network roles. The screenshots alone do not establish
the endpoint's infection state.

### 4.2 DuckDNS resolution and subsequent connection

Visible packet sequence:

| Packet | Observation |
|---|---|
| 1 | DNS A query for `eadzagba1[.]duckdns[.]org` |
| 2 | DNS response containing `198[.]46[.]178[.]133` |
| 3 | TCP SYN from `10.9.11.101:51403` to `198[.]46[.]178[.]133:4877` |
| 4 | TCP SYN/ACK from the remote endpoint |
| 5 | TCP ACK completing the handshake |
| 6 | Traffic identified as a TLS 1.3 Client Hello |
| 8 | Traffic identified as a TLS 1.3 Server Hello |
| 10 onward, in the visible sequence | TLS application data |

**Interpretation:** The visible host resolves a domain, connects to the
returned address, and exchanges traffic identified as TLS.

**Hypothesis:** This connection is a candidate for further command-and-control
investigation given the capture's Remcos label.

**Limitation:** The screenshots do not expose decrypted commands or identify
the process responsible for the connection. C2 activity is not confirmed.

![Wireshark traffic overview](../screenshots/01-wireshark-traffic-overview.png)

### 4.3 geoplugin DNS response

Packet 25 shows:

- Domain: `geoplugin[.]net`
- Record type: A
- Returned address: `178[.]237[.]33[.]50`
- TTL: 5 seconds
- Related request: packet 23

**Interpretation:** A successful DNS resolution is visible.

The DNS response alone does not establish that the host contacted the service,
retrieved location information, or used it for malicious activity.

![geoplugin DNS response](../screenshots/02-dns-geoplugin-response.png)

## 5. Threat Intelligence Enrichment

### 5.1 VirusTotal

The search screenshot shows `178.237.33.50` entered in the URL submission
interface.

The result screenshot is a report for:

`hxxp://178[.]237[.]33[.]50/`

At the time represented by the screenshot:

- 10 of 92 vendors flagged the URL as malicious.
- The displayed HTTP status was 403.
- The displayed content type was application/json.

**Important distinction:** This is a URL report, not a standalone IP-address
reputation report. It also does not establish the reputation of the exact
domain-based request that might have occurred in the capture.

Vendor detections are contextual evidence, not proof that this address
served Remcos C2 in this investigation.

![VirusTotal URL search](../screenshots/03-virustotal-url-search.png)

![VirusTotal URL results](../screenshots/04-virustotal-url-results.png)

### 5.2 AbuseIPDB

The supplied screenshots show:

- IP address: `178[.]237[.]33[.]50`
- Historical reports: 255
- Distinct reporting sources: 9
- Displayed abuse confidence score: 0%
- First reported date: June 26, 2022
- Most recent visible report timestamp: October 24, 2025, 08:02:53 UTC
- Several report rows categorized as brute-force or SSH activity

The page explicitly warns that the reports are old.

**Interpretation:** Historical reports exist, but they do not establish
current abuse, malware-family attribution, or malicious activity by the
analyzed host.

The displayed 0% confidence score should not be treated as proof that the
address is safe.

The VirusTotal and AbuseIPDB observations measure different things and
should not be combined into a definitive malware verdict.

![AbuseIPDB overview](../screenshots/05-abuseipdb-overview.png)

![AbuseIPDB report history](../screenshots/06-abuseipdb-report-history.png)

![AbuseIPDB additional reports](../screenshots/07-abuseipdb-additional-reports.png)

![AbuseIPDB report summary](../screenshots/08-abuseipdb-report-summary.png)

## 6. Observed Indicators and Investigation Leads

Addresses and domains are defanged to prevent accidental navigation.

| Observable | Context | Assessment |
|---|---|---|
| `10.9.11.101` | Internal host | Observed host; not a malicious IOC |
| `10.9.11.1` | DNS resolver | Infrastructure context |
| `eadzagba1[.]duckdns[.]org` | DNS query followed by a connection to its returned IP | Candidate suspicious domain |
| `198[.]46[.]178[.]133` | Remote endpoint on TCP port 4877 | Candidate endpoint for investigation |
| TCP port `4877` | Destination port for the visible TLS connection | Connection detail; not malicious by itself |
| `geoplugin[.]net` | Separate DNS lookup | Contextual observable; malicious role unproven |
| `178[.]237[.]33[.]50` | DNS answer and reputation lookup target | Contextual observable; C2 role unproven |

## 7. Tentative MITRE ATT&CK Mapping

The following are investigation hypotheses, not confirmed adversary techniques.

| Technique | Tactic | Visible evidence | Qualification |
|---|---|---|---|
| T1573 — Encrypted Channel | Command and Control | TLS handshake and application data to `198[.]46[.]178[.]133` | Applicable only if this connection is confirmed as adversary C2; TLS alone is not proof |
| T1571 — Non-Standard Port | Command and Control | Traffic identified as TLS on destination TCP port 4877 | Candidate mapping if malicious C2 and the protocol/port mismatch are validated |

No confirmed ATT&CK mapping is assigned solely because the host queried
`geoplugin[.]net`.

Initial access, persistence, keylogging, credential theft, and exfiltration
are not established by the supplied screenshots.

ATT&CK reference pages:
- https://attack.mitre.org/techniques/T1573/
- https://attack.mitre.org/techniques/T1571/

## 8. Recommended Follow-Up

- Review the complete PCAP.
- Validate the capture source and malware-family labeling.
- Inspect the connection to `198[.]46[.]178[.]133:4877`.
- Review any available TLS metadata and the full connection timeline.
- Identify the endpoint process responsible using authorized endpoint logs.
- Check whether the geoplugin lookup is followed by an actual request.
- Record reputation lookup dates separately from packet timestamps.
- Validate candidate indicators before applying blocking rules.

Example Wireshark display filters:

    dns
    ip.addr == 198.46.178.133
    tcp.port == 4877
    tls
    dns.qry.name == "eadzagba1.duckdns.org"
    dns.qry.name == "geoplugin.net"

## 9. Conclusion

The strongest visible investigation lead is the sequence consisting of
a DuckDNS resolution followed by a TLS connection to
`198[.]46[.]178[.]133` on TCP port 4877.

The geoplugin resolution and reputation screenshots provide additional
context but do not establish a malicious role for that service.

Further packet and endpoint evidence is required to confirm Remcos
attribution, command-and-control behavior, and ATT&CK technique execution.

## 10. Disclaimer

This project is intended for defensive security education.
No live malware is included. Findings are limited to the supplied screenshots,
and suspicious infrastructure was not contacted as part of this report.
