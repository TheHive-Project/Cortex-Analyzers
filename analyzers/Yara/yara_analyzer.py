#!/usr/bin/env python3
# encoding: utf-8
from cortexutils.analyzer import Analyzer

import os
import yara
import requests

import base64
import binascii
import urllib.parse
import re
from html import unescape
from codecs import decode

import tempfile

# Decoding functions, when such payloads are found (not shown in Analyzer template)
def is_base64(s):
    """Try Base64 decoding; return the decoded string or None if it fails"""
    try:
        decoded = base64.b64decode(s, validate=True)
        return decoded.decode('utf-8', errors='ignore')  # Convert bytes to string
    except Exception:
        return None  # Not a valid Base64 string

def is_hex(s):
    """Detect and decode hex-encoded strings"""
    try:
        decoded = binascii.unhexlify(s).decode('utf-8', errors='ignore')
        return decoded
    except Exception:
        return None  # Not a valid hex string

def is_rot13(s):
    """Detect ROT13 encoding"""
    decoded = decode(s, 'rot_13')
    return decoded if decoded != s else None  # If same, it wasn't ROT13

def is_url_encoded(s):
    """Detect and decode URL-encoded payloads"""
    decoded = urllib.parse.unquote(s)
    return decoded if decoded != s else None  # If same, it wasn't encoded

def is_unicode_escape(s):
    """Detect and decode Unicode escape sequences"""
    try:
        decoded = s.encode().decode('unicode_escape')
        return decoded if decoded != s else None
    except Exception:
        return None

def is_html_entity(s):
    """Detect and decode HTML entity encoding"""
    decoded = unescape(s)
    return decoded if decoded != s else None  # If same, it wasn't encoded

def is_xor_static_key(s, key=0x12):
    """Attempt XOR decryption with a static key (useful for malware payloads)"""
    try:
        decoded = ''.join(chr(ord(c) ^ key) for c in s)
        return decoded if decoded.isprintable() else None  # Only return readable text
    except Exception:
        return None

def extract_rule_names_from_file(filepath):
    """Get all YARA rule names from a file."""
    try:
        with open(filepath, "r") as f:
            contents = f.read()
        # This regex looks for lines that start (possibly with whitespace)
        # followed by "rule", then a space and the rule identifier (letters, numbers, or underscores)
        rule_names = re.findall(r'^\s*rule\s+([a-zA-Z0-9_]+)', contents, re.MULTILINE)
        return rule_names
    except Exception as e:
        # If there is an error reading the file, return an empty list.
        return []

def extract_github_info(url):
    """
    Extract the repository identifier, branch, and subdirectory (if any) from a GitHub URL.
    Expected URL formats:
      - https://github.com/owner/repo/tree/main
      - https://github.com/owner/repo/tree/main/subdir
    Returns a dictionary with keys: 'repo' (owner/repo), 'branch', 'path'
    """
    pattern = r'github\.com/([^/]+)/([^/]+)(?:/tree/([^/]+)(?:/(.*))?)?'
    match = re.search(pattern, url)
    if match:
        owner = match.group(1)
        repo = match.group(2)
        branch = match.group(3) if match.group(3) else 'main'
        subdir = match.group(4) if match.group(4) else ""
        return {"repo": f"{owner}/{repo}", "branch": branch, "path": subdir}
    return None

class YaraAnalyzer(Analyzer):
    
    def download_rules_from_github_url(self, url, token):
        """
        Download .yar rule files from a GitHub URL formatted like /tree/main[/optional/subdir]
        using the GitHub API and a PAT. Throws an error via self.error if the repository cannot
        be accessed or if a file download fails.

        :param url: GitHub URL e.g. 'https://github.com/owner/repo/tree/main/subdir'
        :param token: Personal Access Token with repo scope
        :return: List of paths to the downloaded rule files
        """
        info = extract_github_info(url)
        if not info:
            self.error(f"Could not parse the GitHub URL: {url}")

        repo_identifier = info["repo"]
        branch = info["branch"]
        path = info["path"]  # May be empty if no subdirectory is specified

        downloaded_rule_files = []
        headers = {"Authorization": f"token {token}"}

        # Build the API URL: if a subdirectory is provided, include it in the URL
        api_url = f"https://api.github.com/repos/{repo_identifier}/contents"
        if path:
            api_url += f"/{path}"
        api_url += f"?ref={branch}"

        response = requests.get(api_url, headers=headers)
        if response.status_code != 200:
            self.error(f"Error accessing repository contents: {response.status_code} - {response.text}")

        contents = response.json()
        # Normalize to a list if a single file is returned
        if isinstance(contents, dict):
            contents = [contents]
        for item in contents:
            if item["name"].endswith(".yar"):
                download_url = item.get("download_url")
                if download_url:
                    file_response = requests.get(download_url, headers=headers)
                    if file_response.status_code != 200:
                        self.error(f"Error downloading file {item['name']}: {file_response.status_code}")
                    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".yar")
                    tmp_file.write(file_response.content)
                    tmp_file.close()
                    downloaded_rule_files.append(tmp_file.name)

        return downloaded_rule_files


    def __init__(self):
        Analyzer.__init__(self)

        self.rulepaths = self.get_param('config.rules', None, 'No paths for rules provided.')
        if not self.rulepaths:
            self.rulepaths = []  # Ensure it's a list even if nothing was provided
        elif isinstance(self.rulepaths, str):
            self.rulepaths = [self.rulepaths]
            
        self.github_urls = self.get_param('config.github_urls', None, 'No GitHub URLs provided.')
        self.github_token = self.get_param('config.github_token', None, 'No GitHub PAT provided.')

        self.ruleset = []
        self.ignored_rules = []

        for rulepath in self.rulepaths:
            if os.path.isfile(rulepath) and rulepath.endswith('.yar'):
                try:
                    compiled_ruleset = yara.compile(filepath=rulepath)
                    rule_names = extract_rule_names_from_file(rulepath)
                    self.ruleset.append({
                        "compiled": compiled_ruleset,
                        "rule_names": rule_names,
                        "source": rulepath
                    })
                except (yara.SyntaxError, yara.Error, Exception) as e:
                    error_msg = f"Failed to load YARA rule file {rulepath} - {str(e)}"
                    print(f"Warning: {error_msg}")
                    self.ignored_rules.append({"source": rulepath, "error": str(e)})
            
            elif os.path.isdir(rulepath):
                rule_files = [os.path.join(rulepath, f) for f in os.listdir(rulepath) if f.endswith('.yar')]

                if rule_files:
                    for rule_file in rule_files:
                        try:
                            compiled_ruleset = yara.compile(filepath=rule_file)
                            rule_names = extract_rule_names_from_file(rule_file)
                            self.ruleset.append({
                                "compiled": compiled_ruleset,
                                "rule_names": rule_names,
                                "source": rule_file
                            })
                        except (yara.SyntaxError, yara.Error, Exception) as e:
                            error_msg = f"Failed to load YARA rule file {rule_file} - {str(e)}"
                            print(f"Warning: {error_msg}")
                            self.ignored_rules.append({"source": rule_file, "error": str(e)})
                else:
                    print(f"Warning: No .yar files found in directory {rulepath}")

        if self.github_urls and self.github_token:
            for url in self.github_urls:
                github_rule_files = self.download_rules_from_github_url(url, self.github_token)
                for rule_file in github_rule_files:
                    try:
                        compiled_ruleset = yara.compile(filepath=rule_file)
                        rule_names = extract_rule_names_from_file(rule_file)
                        self.ruleset.append({
                            "compiled": compiled_ruleset,
                            "rule_names": rule_names,
                            "source": rule_file
                        })
                    except (yara.SyntaxError, yara.Error, Exception) as e:
                        error_msg = f"Failed to load YARA rule file {rule_file} - {str(e)}"
                        print(f"Warning: {error_msg}")
                        self.ignored_rules.append({"source": rule_file, "error": str(e)})

        if not self.ruleset:
            print("Warning: No valid YARA rules were loaded.")
            
            
    def check(self, file_path):
        """
        Checks a given file against all available YARA rules.

        :param file_path: Path to file
        :return: List of matched rule details, including multiple decoding methods
        """

        results = []
        for idx, rule_obj in enumerate(self.ruleset):
            try:
                # Run the match on the file
                matches = rule_obj["compiled"].match(file_path)
            except Exception as e:
                self.error(f"Error matching file '{file_path}' with ruleset from {rule_obj['source']} (index {idx}): {str(e)}")
                continue
            for match in matches:
                try:
                    decoded_strings = []
                    for s in match.strings:
                        try:
                            matched_text = s[2].decode(errors='ignore')
                        except Exception as e:
                            matched_text = f"<decoding error: {str(e)}>"
    
                        # Apply all relevant decoding methods
                        decoded_b64 = is_base64(matched_text)
                        decoded_hex = is_hex(matched_text)
                        decoded_rot13 = is_rot13(matched_text)
                        decoded_url = is_url_encoded(matched_text)
                        decoded_unicode = is_unicode_escape(matched_text)
                        decoded_html = is_html_entity(matched_text)
                        decoded_xor = is_xor_static_key(matched_text)
    
                        decoded_strings.append({
                            "offset": s[0],
                            "matched": matched_text,
                            "base64_decoded": decoded_b64 if decoded_b64 else "N/A",
                            "hex_decoded": decoded_hex if decoded_hex else "N/A",
                            "rot13_decoded": decoded_rot13 if decoded_rot13 else "N/A",
                            "url_decoded": decoded_url if decoded_url else "N/A",
                            "unicode_decoded": decoded_unicode if decoded_unicode else "N/A",
                            "html_decoded": decoded_html if decoded_html else "N/A",
                            "xor_decoded": decoded_xor if decoded_xor else "N/A"
                        })
                    results.append({
                        "rule": match.rule,
                        "namespace": match.namespace if hasattr(match, "namespace") else "N/A",
                        "strings": decoded_strings,
                        "meta": match.meta
                    })
                except Exception as e:
                    self.error(f"Error processing match from rule '{match.rule}' in file {rule_obj['source']}: {str(e)}")
        return results


    def summary(self, raw):
        taxonomies = []
        namespace = "Yara"
        predicate = "Match"

        if isinstance(raw, list):
            match_count = len(raw)
        elif isinstance(raw, dict) and "results" in raw:
            match_count = len(raw["results"])
        else:
            match_count = 0
        
        nb_of_rules = sum(len(rule_obj.get("rule_names", [])) for rule_obj in self.ruleset)
        
        value = f"{match_count}/{nb_of_rules} rule(s)"
        level = "safe" if match_count == 0 else "malicious"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type == 'file':
            matches = self.check(self.get_param('file'))
            summary = self.summary(matches)
            rule_names = []
            try:
                for ruleset in self.ruleset:
                    rule_names.extend([rule.identifier for rule in ruleset])
            except:
                pass
            try:
                for rule_obj in self.ruleset:
                    rule_names.extend(rule_obj.get("rule_names", []))
            except:
                pass
            
            
            output = {
                "results": matches,
                "summary": summary,
                "rules_tested": sum(len(rule_obj.get("rule_names", [])) for rule_obj in self.ruleset),
                "rulenames": rule_names,
                "total_yar_files": len(self.ruleset),
                "ignored_rules": self.ignored_rules
            }
            self.report(output)
        else:
            self.error('Wrong data type.')


if __name__ == '__main__':
    YaraAnalyzer().run()