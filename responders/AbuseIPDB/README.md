# AbuseIPDB Responder

Reports IP addresses to AbuseIPDB.

## Configuration

- **key**: Your AbuseIPDB API key
- **categories**: One or more categories (see below)
- **comment**: Optional comment (max 1024 chars)

### Categories

DNS Compromise, DNS Poisoning, Fraud Orders, DDoS Attack, FTP Brute-Force, Ping of Death, Phishing, Fraud VoIP, Open Proxy, Web Spam, Email Spam, Blog Spam, VPN IP, Port Scan, Hacking, SQL Injection, Spoofing, Brute Force, Bad Web Bot, Exploited Host, Web App Attack, SSH, IoT Targeted

## Before you use this

Everytime you run it, configure the responder in Cortex with the correct categories **before** running it from TheHive. Categories cannot be changed at runtime, as of today.

Wrong categories = bad data in AbuseIPDB. Always validate Cortex configuration before using.
