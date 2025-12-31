#!/usr/bin/env python3
# encoding: utf-8

"""
Office 365 ATP Safe Links Decoder Analyzer for TheHive/Cortex
Extracts original URLs from Microsoft Safe Links

Author: Louis HUSSON
License: AGPL-V3
"""

import re
import urllib.parse
from typing import Optional
from cortexutils.analyzer import Analyzer


class SafeLinksDecoder(Analyzer):
    """
    Analyzer to decode Office 365 ATP Safe Links.
    
    Safe Links are Microsoft's URL wrapping service that protects users by
    checking links before they are accessed. This analyzer extracts the
    original destination URL from the wrapped Safe Link.
    """
    
    def __init__(self):
        Analyzer.__init__(self)

    def decode_safelink(self, safelink: str) -> Optional[str]:
        """
        Decode an Office 365 ATP Safe Link to extract the original URL.
        
        Microsoft Safe Links use URL encoding to wrap the original URL in
        query parameters. This method tries multiple common patterns used
        by different O365 regions and configurations.
        
        Args:
            safelink: The Safe Link URL to decode (must contain safelinks.protection.outlook.com)
            
        Returns:
            The original decoded URL if found, None otherwise
            
        Example:
            Input:  https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.com
            Output: https://example.com
        """
        # Common Safe Links patterns observed in the wild
        # Microsoft uses different parameter names and encodings depending on tenant config
        patterns = [
            # Pattern 1: url= parameter (most common, ~90% of cases)
            # Used by default O365 ATP Safe Links configuration
            r'[?&]url=([^&]+)',
            
            # Pattern 2: data= parameter (alternative encoding)
            # Sometimes used in forwarded emails or specific tenant configurations
            r'[?&]data=([^&]+)',
            
            # Pattern 3: Direct domain pattern with explicit url parameter
            # Explicit pattern for additional validation
            r'https?://[^/]*\.safelinks\.protection\.outlook\.com/\?url=([^&]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, safelink, re.IGNORECASE)
            if match:
                encoded_url = match.group(1)
                try:
                    # First-level URL decode: %3A -> :, %2F -> /, etc.
                    decoded_url = urllib.parse.unquote(encoded_url)
                    
                    # Handle double-encoding (happens in forwarded emails)
                    # If the decoded URL still contains % and starts with http, decode again
                    if decoded_url.startswith('http') and '%' in decoded_url:
                        decoded_url = urllib.parse.unquote(decoded_url)
                    
                    return decoded_url
                    
                except Exception as e:
                    # Log error but don't stop - try next pattern
                    self.error(f"Error decoding URL with pattern '{pattern}': {e}")
                    continue
        
        # No pattern matched - return None
        return None

    def is_safelink(self, url: str) -> bool:
        """
        Check if the provided URL is a Microsoft Safe Link.
        
        Safe Links always contain 'safelinks.protection.outlook.com' in their domain,
        regardless of region (nam, eur, can, aus, etc.)
        
        Args:
            url: The URL to check
            
        Returns:
            True if the URL is a Safe Link, False otherwise
        """
        return bool(re.search(
            r'\.safelinks\.protection\.outlook\.com', 
            url, 
            re.IGNORECASE
        ))

    def run(self):
        """
        Main analyzer execution method.
        
        This method is called by Cortex when the analyzer is invoked.
        It performs the following steps:
        1. Retrieve the observable data (URL)
        2. Verify it's a Safe Link
        3. Decode the Safe Link to extract original URL
        4. Report results back to Cortex/TheHive
        """
        try:
            # Get the observable data (the URL to analyze)
            data = self.get_data()
            
            # Validation: Check if this is actually a Safe Link
            if not self.is_safelink(data):
                # Not a Safe Link - report this and exit normally
                # This is NOT an error, just means the analyzer doesn't apply
                self.report({
                    'is_safelink': False,
                    'original_url': data,
                    'message': 'This URL is not an Office 365 ATP Safe Link'
                })
                return

            # Attempt to decode the Safe Link
            decoded_url = self.decode_safelink(data)
            
            if not decoded_url:
                # Could not decode - this IS an error since we confirmed it's a Safe Link
                self.error("Could not decode the Safe Link - no matching pattern found")
                return
            
            # Success - build the result report
            result = {
                'is_safelink': True,
                'original_url': decoded_url,
                'safelink_domain': self._extract_safelink_domain(data),
                'safelink_input': data  # Include original for reference
            }

            # Send report to Cortex
            # This triggers the artifacts() and summary() methods automatically
            self.report(result)

        except Exception as e:
            # Catch-all for unexpected errors
            self.error(f"Unhandled exception during analysis: {e}")

    def _extract_safelink_domain(self, url: str) -> Optional[str]:
        """
        Extract the Safe Links domain from the URL.
        
        This identifies which regional Safe Links gateway was used
        (e.g., nam02.safelinks.protection.outlook.com = North America region 2)
        
        Args:
            url: The Safe Link URL
            
        Returns:
            The full Safe Links domain, or None if not found
            
        Example:
            Input:  https://nam02.safelinks.protection.outlook.com/?url=...
            Output: nam02.safelinks.protection.outlook.com
        """
        match = re.search(
            r'https?://([^/]*\.safelinks\.protection\.outlook\.com)', 
            url, 
            re.IGNORECASE
        )
        return match.group(1) if match else None

    def summary(self, raw):
        """
        Generate summary taxonomies for TheHive short report.
        
        Taxonomies are displayed in TheHive's observable list and provide
        quick visual indicators of the analysis result.
        
        Args:
            raw: The report data dict passed to self.report() in run()
            
        Returns:
            Dict containing list of taxonomies
            
        Taxonomy Format:
            namespace:predicate="value" with a level (info/safe/suspicious/malicious)
        """
        taxonomies = []
        namespace = "SafeLinks"
        
        # Check if this was actually a Safe Link
        is_safelink = raw.get('is_safelink', True)  # Default True for backward compat
        
        if not is_safelink:
            # Not a Safe Link - single taxonomy to indicate this
            taxonomies.append(
                self.build_taxonomy("info", namespace, "Status", "Not a SafeLink")
            )
        else:
            # Successfully decoded a Safe Link
            original_url = raw.get('original_url', 'N/A')
            
            # Primary taxonomy: indicate successful decoding
            taxonomies.append(
                self.build_taxonomy("info", namespace, "Decoded", "Success")
            )
            
            # Secondary taxonomy: show the original domain for quick reference
            try:
                parsed = urllib.parse.urlparse(original_url)
                domain = parsed.netloc
                if domain:
                    taxonomies.append(
                        self.build_taxonomy("info", namespace, "OriginalDomain", domain)
                    )
            except Exception:
                # If URL parsing fails, skip domain taxonomy
                pass
        
        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        """
        Extract artifacts (new observables) from the analysis results.
        
        This method is automatically called by Cortex after run() completes.
        It allows the analyzer to create new observables in TheHive based
        on the analysis findings.
        
        Args:
            raw: The report data dict passed to self.report() in run()
            
        Returns:
            List of artifact dicts (each artifact can becomes an observable in TheHive)
            
        Artifacts Created:
            1. url artifact: The decoded original URL (automatically if enabled)
            2. domain artifact: The domain extracted from the decoded URL
        """
        artifacts = []
        is_safelink = raw.get('is_safelink', True)
        if not is_safelink:
            # Not a Safe Link, no artifacts to create
            return artifacts
        
        # Extract the decoded URL from analysis results
        original_url = raw.get('original_url')
        if not original_url:
            # No decoded URL found (shouldn't happen, but defensive coding)
            return artifacts
        
        # Artifact 1: Create a URL observable for the decoded link
        artifacts.append(
            self.build_artifact(
                'url',                                      # Observable type
                original_url,                               # Observable value
                tags=['SafeLinks:Decoded', 'AutoExtracted', "autoImport:true"],
            )
        )
        
        # Artifact 2: Extract and create a domain observable
        # This allows analysts to pivot on the domain separately
        try:
            parsed = urllib.parse.urlparse(original_url)
            domain = parsed.netloc
            
            if domain:
                artifacts.append(
                    self.build_artifact(
                        'domain',                           # Observable type
                        domain,                             # Observable value (just the domain)
                        tags=['SafeLinks:OriginalDomain', 'AutoExtracted']
                    )
                )
        except Exception:
            # If domain extraction fails, continue without it
            # We still have the URL artifact, so analysis is useful
            pass
        
        return artifacts


if __name__ == "__main__":
    # Entry point when script is executed directly
    # Cortex calls this when running the analyzer
    SafeLinksDecoder().run()