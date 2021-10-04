# Set timezone
TIMEZONE = 'UTC'

# Taxii info
TAXII_HOST = '10.1.108.166'
TAXII_PORT = 9000
TAXII_DISCOVERY_PATH = None
TAXII_USE_HTTPS = False
TAXII_DISCOVERY_URL = '/services/discovery'
TAXII_VERSION = '1.1'
TAXII_HEADER = None
TAXII_USR = 'admin'
TAXII_PASS = 'admin'

# ElasticSearch info
ES_HOST = '10.1.108.165'
ES_PORT = 9200
ES_USR = 'elastic'
ES_PASS = 'r88VUW8WNMPkpPe6'

# Index of data
INDICATOR_INDEX = 'threat_intelligence_indicator'
TYPE_INDEX = 'threat_intelligence_type_indicator'
PROJECT_INDEX = 'threat_intelligence_project'

# Map 'indicator type' to 'collection' (cannot add other lists, can only add elements to the list below)
MY_COLLECTION = ['bitcoinaddress', 'yara', 'cve', 'email', 'sslcertfingerprint', 'ja3', 'mutex']
MALICIOUS_IP_COLLECTION = ['ip', 'ipv4', 'ipv6']
Malicious_URL_COLLECTION = ['hostname', 'domain', 'url']
MD5_HASH_COLLECTION = []
SHA1_HASH_COLLECTION = []
SHA256_HASH_COLLECTION = ['sha256']

# STIX Header (Choose whatever you want, this is just a marker to distinguish STIX objects from different sources)
STIX_NAMESPACE = "VNPTSOC"
