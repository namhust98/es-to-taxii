from stix.common.vocabs import IndicatorType_1_1

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

# Map 'custom indicator type' to 'stix indicator type' (cannot add other lists, can only add elements to the list below)
ANONYMIZATION = ['test 2']
C2 = ['test 3']
COMPROMISED_PKI_CERTIFICATE = []
DOMAIN_WATCHLIST = []
EXFILTRATION = []
FILE_HASH_WATCHLIST = []
HOST_CHARACTERISTICS = []
IMEI_WATCHLIST = []
IMSI_WATCHLIST = []
IP_WATCHLIST = []
LOGIN_NAME = []
MALICIOUS_EMAIL = []
MALWARE_ARTIFACTS = []
URL_WATCHLIST = []

# Map 'indicator type' to 'collection' (cannot add other lists, can only add elements to the list below)
MY_COLLECTION = []
MALICIOUS_IP_COLLECTION = [IndicatorType_1_1.TERM_IP_WATCHLIST,
                           IndicatorType_1_1.TERM_HOST_CHARACTERISTICS]
Malicious_URL_COLLECTION = [IndicatorType_1_1.TERM_URL_WATCHLIST,
                            IndicatorType_1_1.TERM_DOMAIN_WATCHLIST]
MD5_HASH_COLLECTION = []
SHA1_HASH_COLLECTION = []
SHA256_HASH_COLLECTION = [IndicatorType_1_1.TERM_FILE_HASH_WATCHLIST]

# STIX Header (Choose whatever you want, this is just a marker to distinguish STIX objects from different sources)
STIX_HEADER_DESCRIPTION = 'vnpt stix'
STIX_NAMESPACE = "VNPTSOC"
