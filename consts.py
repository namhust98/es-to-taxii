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
ES_HOST = '192.168.186.128'
ES_PORT = 9200
ES_USR = 'admin'
ES_PASS = 'admin'

# Index of data
INDICATOR_INDEX = 'threat_intelligence_indicator'
TYPE_INDEX = 'threat_intelligence_type'
PROJECT_INDEX = 'threat_intelligence_project'

# Map 'indicator type' to 'collection' (cannot add other lists, can only add elements to the list below)
MY_COLLECTION = []
MALICIOUS_IP_COLLECTION = []
Malicious_URL_COLLECTION = []
MD5_HASH_COLLECTION = []
SHA1_HASH_COLLECTION = []
SHA256_HASH_COLLECTION = []

# STIX Header (Choose whatever you want, this is just a marker to distinguish STIX objects from different sources)
STIX_HEADER_DESCRIPTION = 'vnpt stix'
STIX_NAMESPACE = "VNPTSOC"
