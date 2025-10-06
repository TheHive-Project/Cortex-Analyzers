#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import re
import ipaddress
from validators import url as validate_url_lib
from urllib.parse import urlparse
import idna

class ValidateObservable(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

    def run(self):
        # Validate based on data type
        if self.data_type == 'ip':
            result = self.validate_ip(self.get_data())
        elif self.data_type == 'domain':
            result = self.validate_domain(self.get_data())
        elif self.data_type == 'url':
            result = self.validate_url(self.get_data())
        elif self.data_type == 'fqdn':
            result = self.validate_fqdn(self.get_data())
        elif self.data_type == 'mail':
            result = self.validate_email(self.get_data())
        elif self.data_type == 'hash':
            result = self.validate_hash(self.get_data())
        elif self.data_type == 'filename':
            result = self.validate_filename(self.get_data())
        elif self.data_type == 'uri_path':
            result = self.validate_uri_path(self.get_data())
        elif self.data_type == 'user-agent':
            result = self.validate_user_agent(self.get_data())
        else:
            self.error(f"Unsupported data type: {self.data_type}")

        self.report(result)

    def contains_bidi_override(self, value):
        bidi_override_chars = ["\u202E", "\u202D", "\u200E", "\u200F", "\u2066", "\u2067"]
        for char in bidi_override_chars:
            if char in value:
                return f"Contains Unicode bidirectional override character U+{ord(char):04X}"
        return None

    def validate_ip(self, ip):
        try:
     
            if "/" in ip:  # CIDR range
                ipaddress.ip_network(ip, strict=False)
                return {
                    "status": "valid",
                    "type": "IP range",
                    "value": ip
                }
            else:  # Single IP
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_loopback:
                    return {
                        "status": "valid",
                        "type": "IP address",
                        "value": ip,
                        "note": "Loopback IP address"
                    }
                elif ip_obj.is_private:
                    return {
                        "status": "valid",
                        "type": "IP address",
                        "value": ip,
                        "note": "Private IP address"
                    }
                elif ip_obj.is_reserved:
                    return {
                        "status": "valid",
                        "type": "IP address",
                        "value": ip,
                        "note": "Reserved IP address"
                    }
                else:
                    return {
                        "status": "valid",
                        "type": "IP address",
                        "value": ip
                    }
        except ValueError:
            return {
                "status": "invalid",
                "type": "IP address",
                "value": ip
            }
            
    def validate_domain(self, domain):
        try:
            # Convert non-ASCII domains to Punycode
            punycode_domain = idna.encode(domain).decode()

            # Check for Punycode (IDN) and unusual characters
            if domain.startswith("xn--"):
                return {
                    "status": "suspicious",
                    "type": "Domain",
                    "value": domain,
                    "reason": "Domain uses Punycode, which may indicate an internationalized domain name (IDN)"
                }

            # Validate the domain structure
            domain_regex = r'^(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$'
            if len(punycode_domain) > 255:
                return {
                    "status": "invalid",
                    "type": "Domain",
                    "value": domain,
                    "reason": "Exceeds maximum length of 255 characters"
                }
            if re.match(domain_regex, punycode_domain):
                if re.search(r"[^a-zA-Z0-9.-]", domain):
                    return {
                        "status": "suspicious",
                        "type": "Domain",
                        "value": domain,
                        "reason": "Domain is valid but contains IDN or unusual characters"
                    }
                return {
                    "status": "valid",
                    "type": "Domain",
                    "value": domain
                }
            else:
                return {
                    "status": "invalid",
                    "type": "Domain",
                    "value": domain
                }
        except idna.IDNAError:
            return {
                "status": "invalid",
                "type": "Domain",
                "value": domain,
                "reason": "Invalid internationalized domain name"
            }

        
        
    def validate_url(self, url):
        bidi_check = self.contains_bidi_override(url)
        if bidi_check:
            return {
                "status": "suspicious",
                "type": "URL",
                "value": url,
                "reason": bidi_check
            }

        parsed = urlparse(url)
        if not parsed.scheme and not parsed.netloc:
            # Validate as a domain if scheme and netloc are missing
            return self.validate_domain(url)

        if all([parsed.scheme, parsed.netloc]):
            if parsed.netloc.startswith("xn--"):
                return {
                    "status": "suspicious",
                    "type": "URL",
                    "value": url,
                    "reason": "URL contains a Punycode domain, which may indicate an internationalized domain name (IDN)"
                }

            if re.search(r"[^a-zA-Z0-9:/?&=._-]", url):
                return {
                    "status": "suspicious",
                    "type": "URL",
                    "value": url,
                    "reason": "Contains unusual characters"
                }
            return {
                "status": "valid",
                "type": "URL",
                "value": url
            }
        return {
            "status": "invalid",
            "type": "URL",
            "value": url,
            "reason": "Malformed or missing scheme/netloc"
        }

    def validate_fqdn(self, fqdn):
        fqdn_regex = (
            r'^(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$'
        )
        if len(fqdn) > 255:
            return {
                "status": "invalid",
                "type": "FQDN",
                "value": fqdn,
                "reason": "Exceeds maximum length of 255 characters"
            }
        if fqdn.startswith("xn--"):
            return {
                "status": "suspicious",
                "type": "FQDN",
                "value": fqdn,
                "reason": "FQDN uses Punycode, which may indicate an internationalized domain name (IDN)"
            }
        if re.match(fqdn_regex, fqdn):
            if re.search(r"[^a-zA-Z0-9.-]", fqdn):
                return {
                    "status": "suspicious",
                    "type": "FQDN",
                    "value": fqdn,
                    "reason": "Contains unusual characters"
                }
            return {
                "status": "valid",
                "type": "FQDN",
                "value": fqdn
            }
        else:
            return {
                "status": "invalid",
                "type": "FQDN",
                "value": fqdn
            }

    def validate_email(self, email):
        bidi_check = self.contains_bidi_override(email)
        if bidi_check:
            return {
                "status": "suspicious",
                "type": "Email",
                "value": email,
                "reason": bidi_check
            }

        email_regex = (
            r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
        )
        if len(email) > 254:
            return {
                "status": "invalid",
                "type": "Email",
                "value": email,
                "reason": "Exceeds maximum length of 254 characters"
            }
        if re.match(email_regex, email):
            if re.search(r"[^a-zA-Z0-9@._%+-]", email):
                return {
                    "status": "suspicious",
                    "type": "Email",
                    "value": email,
                    "reason": "Contains unusual characters"
                }
            return {
                "status": "valid",
                "type": "Email",
                "value": email
            }
        else:
            return {
                "status": "invalid",
                "type": "Email",
                "value": email
            }

    def validate_hash(self, hash_value):
        hash_regex = {
            "MD5": r"^[a-fA-F0-9]{32}$",
            "SHA1": r"^[a-fA-F0-9]{40}$",
            "SHA256": r"^[a-fA-F0-9]{64}$",
            "SHA512": r"^[a-fA-F0-9]{128}$"
        }
        for hash_type, regex in hash_regex.items():
            if re.match(regex, hash_value):
                return {
                    "status": "valid",
                    "type": f"{hash_type} Hash",
                    "value": hash_value
                }
        return {
            "status": "invalid",
            "type": "Hash",
            "value": hash_value,
            "reason": "Does not match known hash formats (supported types: MD5, SHA1, SHA256, SHA512)"
        }

    def validate_filename(self, filename):
        bidi_check = self.contains_bidi_override(filename)
        if bidi_check:
            return {
                "status": "suspicious",
                "type": "Filename",
                "value": filename,
                "reason": bidi_check
            }

        invalid_chars = r"[<>:\"/\\|?*]"
        if len(filename) > 255:
            return {
                "status": "invalid",
                "type": "Filename",
                "value": filename,
                "reason": "Exceeds maximum length of 255 characters"
            }
        if re.search(invalid_chars, filename):
            return {
                "status": "invalid",
                "type": "Filename",
                "value": filename,
                "reason": "Contains invalid characters"
            }
        if re.search(r"\.\w{2,4}(\.\w{2,4})", filename):
            return {
                "status": "suspicious",
                "type": "Filename",
                "value": filename,
                "reason": "Contains multiple extensions that may confuse users"
            }
        return {
            "status": "valid",
            "type": "Filename",
            "value": filename
        }

        
    def validate_uri_path(self, uri_path):
        parsed = urlparse(uri_path)
        if parsed.path and parsed.path.startswith("/"):
            return {
                "status": "valid",
                "type": "URI Path",
                "value": uri_path
            }
        return {
            "status": "invalid",
            "type": "URI Path",
            "value": uri_path,
            "reason": "Does not start with '/' or is malformed"
        }

    def validate_user_agent(self, user_agent):
        if len(user_agent) > 512:
            return {
                "status": "invalid",
                "type": "User-Agent",
                "value": user_agent,
                "reason": "Exceeds maximum length of 512 characters"
            }
        if re.search(r"[\x00-\x1F\x7F]", user_agent):
            return {
                "status": "invalid",
                "type": "User-Agent",
                "value": user_agent,
                "reason": "Contains control characters"
            }
        return {
            "status": "valid",
            "type": "User-Agent",
            "value": user_agent
        }

    def summary(self, raw):
        taxonomies = []
        namespace = "ValidateObs"
        predicate = self.data_type

        # Determine level based on status
        status = raw.get("status")
        if status == "valid":
            level = "info"
        elif status == "suspicious":
            level = "suspicious"
        else:
            level = "suspicious"

        # Build taxonomy based on validation result
        taxonomies.append(
            self.build_taxonomy(
                level, namespace, predicate, status)
        )
        return {"taxonomies": taxonomies}

if __name__ == "__main__":
    ValidateObservable().run()
