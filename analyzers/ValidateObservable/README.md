The **ValidateObservable** analyzer is designed to validate multiple observable datatypes. 

* _ip_
* _domain_
* _url_
* _fqdn_
* _mail_
* _hash_
* _filename_
* _uri_path_
* _user-agent_

## Supported Data Types / Features
1. **IP Addresses**

    - Validates individual IPs and CIDR ranges.
    - Flags reserved, private, and loopback IPs with appropriate notes.

2. **Domains**

    - Detects valid domain names.
    - Flags domains using Punycode (e.g., xn--) as suspicious.
    - Identifies unusual characters in domain names.

3. **URLs**

    - Validates URLs with or without schemes.
    - Flags URLs containing Punycode domains or unusual characters as suspicious.
    - Detects malformed URLs.

4. **Fully Qualified Domain Names (FQDNs)**

    - Validates FQDNs for proper structure and length.
    - Flags FQDNs using Punycode and unusual characters as suspicious.

5. **Emails**

    - Checks email structure for validity.
    - Detects unusual characters in email addresses.
    - Validates against length constraints.

6. **File Hashes**

    - Validates MD5, SHA1, SHA256, and SHA512 hash formats.

7. **Filenames**

    - Flags invalid characters in filenames (<, >, :, |, etc.).
    - Detects multiple extensions (for example, .txt.exe) as suspicious.
    - Identifies Unicode bidirectional override characters (U+202E, etc.) to prevent obfuscated extensions.

8. **URI Paths**

    - Ensures paths start with / and are well-formed.

9. **User Agents**

    - Checks for excessive length and control characters.

## Special Features

- **Unicode Detection**:
    - Identifies Unicode bidirectional override characters (for example, U+202E) across domains, URLs, emails, filenames, and more.
    - Flags their usage as suspicious to prevent obfuscation attacks.
- **Punycode Detection**:
    - Flags internationalized domain names (IDNs) using xn-- prefix or uncommon characters.
- **Structured Output**:
    - Returns valid, invalid, or suspicious statuses with detailed reasons.
- **Short reports**:
    - Generates short reports to indicate the validation status and risk level : info (blue) or invalid / suspicious (orange).