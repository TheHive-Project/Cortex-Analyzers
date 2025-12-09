BASE_URL = "https://www.virustotal.com/api/v3"

# API endpoints
IP_ADDRESSES = "ip_addresses"
DOMAINS = "domains"
URLS = "urls"
FILES = "files"
MITRE = "behaviour_mitre_trees"

# Request headers and client configuration
X_TOOL = "GTI-TheHive"
USER_AGENT = "GTI-TheHive-1.0"
TIMEOUT = 60

# User-facing messages for HTTP status codes
STATUS_CODE_MESSAGES = {
    400: "Invalid request parameters provided for: {ioc_value}.",
    401: "Authentication failed. Please check your API key and permissions.",
    403: "Authentication failed. Please check your API key and permissions.",
    404: "No google threat intelligence data found for: {ioc_value}.",
    429: "Request rate limit exceeded. Please try again in a few moments.",
    500: "Google Threat intelligence service is temporarily unavailable. Please try again later.",
    502: "Google Threat intelligence service is temporarily unavailable. Please try again later.",
    503: "Google Threat intelligence service is temporarily unavailable. Please try again later.",
    504: "Google Threat intelligence service is temporarily unavailable. Please try again later.",
}

# Relationship attribute definitions
BASE_RELATIONSHIPS = (
    "campaigns,collections,malware_families,related_threat_actors,software_toolkits,"
    "comments,reports,vulnerabilities"
)
ATTRIBUTES = (
    "name,id,collection_type,description,origin,source_regions_hierarchy,"
    "targeted_industries_tree,targeted_regions_hierarchy"
)
VULNERABILITIES_ATTRIBUTES = "alt_names,name,executive_summary,counters,priority,status,sources,tags,cvss,origin"
COMMENTS_ATTRIBUTES = "tags,text,date,html,votes"
REPORTS_ATTRIBUTES = (
    "name,id,collection_type,origin,source_regions_hierarchy,"
    "targeted_industries_tree,targeted_regions_hierarchy"
)
URLS_ATTRIBUTES = "url"
RESOLUTIONS_ATTRIBUTES = "ip_address_last_analysis_stats,host_name_last_analysis_stats,resolver,date,host_name,ip_address"
REFERRER_FILES_ATTRIBUTES = "id"
CONTACTED_IPS_ATTRIBUTES = "id"
CONTACTED_URLS_ATTRIBUTES = "url"
CONTACTED_DOMAINS_ATTRIBUTES = "id"
FILE_SANDBOX_ATTRIBUTES = (
    "sandbox_name,analysis_date,last_modification_date,behash,command_executions,"
    "has_memdump,has_pcap,hosts_file,sigma_analysis_results,signature_matches,"
    "dns_lookups,verdicts,tags,verdict_confidence"
)

# Relationship query parameters
IP_RELATIONSHIPS_PARAMS = {
    "relationships": f"{BASE_RELATIONSHIPS},urls,resolutions,referrer_files",
    "relationship_attributes[campaigns]": ATTRIBUTES,
    "relationship_attributes[collections]": ATTRIBUTES,
    "relationship_attributes[malware_families]": ATTRIBUTES,
    "relationship_attributes[related_threat_actors]": ATTRIBUTES,
    "relationship_attributes[software_toolkits]": ATTRIBUTES,
    "relationship_attributes[reports]": REPORTS_ATTRIBUTES,
    "relationship_attributes[comments]": COMMENTS_ATTRIBUTES,
    "relationship_attributes[vulnerabilities]": VULNERABILITIES_ATTRIBUTES,
    "relationship_attributes[urls]": URLS_ATTRIBUTES,
    "relationship_attributes[resolutions]": RESOLUTIONS_ATTRIBUTES,
    "relationship_attributes[referrer_files]": REFERRER_FILES_ATTRIBUTES,
}

DOMAIN_RELATIONSHIPS_PARAMS = {
    "relationships": f"{BASE_RELATIONSHIPS},urls,resolutions,referrer_files",
    "relationship_attributes[campaigns]": ATTRIBUTES,
    "relationship_attributes[collections]": ATTRIBUTES,
    "relationship_attributes[malware_families]": ATTRIBUTES,
    "relationship_attributes[related_threat_actors]": ATTRIBUTES,
    "relationship_attributes[software_toolkits]": ATTRIBUTES,
    "relationship_attributes[reports]": REPORTS_ATTRIBUTES,
    "relationship_attributes[comments]": COMMENTS_ATTRIBUTES,
    "relationship_attributes[vulnerabilities]": VULNERABILITIES_ATTRIBUTES,
    "relationship_attributes[urls]": URLS_ATTRIBUTES,
    "relationship_attributes[resolutions]": RESOLUTIONS_ATTRIBUTES,
    "relationship_attributes[referrer_files]": REFERRER_FILES_ATTRIBUTES,
}

FILE_RELATIONSHIPS_PARAMS = {
    "relationships": f"{BASE_RELATIONSHIPS},contacted_ips,contacted_urls,contacted_domains,behaviours",
    "relationship_attributes[campaigns]": ATTRIBUTES,
    "relationship_attributes[collections]": ATTRIBUTES,
    "relationship_attributes[malware_families]": ATTRIBUTES,
    "relationship_attributes[related_threat_actors]": ATTRIBUTES,
    "relationship_attributes[software_toolkits]": ATTRIBUTES,
    "relationship_attributes[reports]": REPORTS_ATTRIBUTES,
    "relationship_attributes[comments]": COMMENTS_ATTRIBUTES,
    "relationship_attributes[vulnerabilities]": VULNERABILITIES_ATTRIBUTES,
    "relationship_attributes[behaviours]": FILE_SANDBOX_ATTRIBUTES,
    "relationship_attributes[contacted_ips]": CONTACTED_IPS_ATTRIBUTES,
    "relationship_attributes[contacted_urls]": CONTACTED_URLS_ATTRIBUTES,
    "relationship_attributes[contacted_domains]": CONTACTED_DOMAINS_ATTRIBUTES,
}

URL_RELATIONSHIPS_PARAMS = {
    "relationships": f"{BASE_RELATIONSHIPS},contacted_ips,referrer_files,contacted_domains",
    "relationship_attributes[campaigns]": ATTRIBUTES,
    "relationship_attributes[collections]": ATTRIBUTES,
    "relationship_attributes[malware_families]": ATTRIBUTES,
    "relationship_attributes[related_threat_actors]": ATTRIBUTES,
    "relationship_attributes[software_toolkits]": ATTRIBUTES,
    "relationship_attributes[reports]": REPORTS_ATTRIBUTES,
    "relationship_attributes[comments]": COMMENTS_ATTRIBUTES,
    "relationship_attributes[vulnerabilities]": VULNERABILITIES_ATTRIBUTES,
    "relationship_attributes[contacted_ips]": CONTACTED_IPS_ATTRIBUTES,
    "relationship_attributes[referrer_files]": REFERRER_FILES_ATTRIBUTES,
    "relationship_attributes[contacted_domains]": CONTACTED_DOMAINS_ATTRIBUTES,
}

# Limits and pagination
MAX_FILE_SIZE = 32 * 1024 * 1024
POLLING_INTERVAL = 15
MAX_PAGINATION_ITERATIONS = 3
DEFAULT_LIMIT = 40

# Mapping for extracting attributes per relationship
RELATIONSHIP_ATTRIBUTES_MAP = {
    "comments": COMMENTS_ATTRIBUTES,
    "reports": REPORTS_ATTRIBUTES,
    "vulnerabilities": VULNERABILITIES_ATTRIBUTES,
    "urls": URLS_ATTRIBUTES,
    "resolutions": RESOLUTIONS_ATTRIBUTES,
    "referrer_files": REFERRER_FILES_ATTRIBUTES,
    "contacted_ips": CONTACTED_IPS_ATTRIBUTES,
    "contacted_urls": CONTACTED_URLS_ATTRIBUTES,
    "contacted_domains": CONTACTED_DOMAINS_ATTRIBUTES,
    "behaviours": FILE_SANDBOX_ATTRIBUTES,
}

# endpoint mapping based on IOC type
IOC_ENDPOINT_MAP = {
    "ip": IP_ADDRESSES,
    "domain": DOMAINS,
    "url": URLS,
    "file": FILES,
}

# keys for extracting IOC relationships
IOC_RELATIONSHIP_KEYS = {
    "urls",
    "referrer_files",
    "contacted_ips",
    "contacted_urls",
    "contacted_domains",
}

IOC_EXTRACTION_MAP = {
    "urls": ("url", "url", "attributes"),
    "contacted_urls": ("url", "url", "attributes"),
    "contacted_ips": ("ip", "id", None),
    "referrer_files": ("hash", "id", None),
    "contacted_domains": ("domain", "id", None),
}

# relationships containing region/industry hierarchy
REGION_AND_INDUSTRY_RELATIONSHIPS = {
    "reports",
    "collections",
    "campaigns",
    "malware_families",
    "related_threat_actors",
    "software_toolkits",
}
