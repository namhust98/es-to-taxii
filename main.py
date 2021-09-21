import cabby

from consts import *

from stix.core import STIXPackage, STIXHeader, Campaigns
from stix.indicator import Indicator
from stix.common.vocabs import IndicatorType_1_1, VocabString
from stix.campaign import Campaign, Names

from cybox.utils import Namespace
from cybox.core import Observable

from mixbox.idgen import set_id_namespace
from elasticsearch import Elasticsearch

namespace = Namespace("https://sec.vnpt.vn", STIX_NAMESPACE)
set_id_namespace(namespace)


def query_es(index: str, id):
    """ Query data from ElasticSearch """

    # Connect to ElasticSearch
    es = Elasticsearch([{'host': ES_HOST, 'port': ES_PORT}],
                       http_auth=(ES_USR, ES_PASS))

    # Query in ElasticSearch
    if id is None:
        data = es.search(index=index)
    else:
        data = es.search(index=index, body={"query": {"match": {"_id": id}}})

    # Close ElasticSearch client and return data
    es.close()
    return data


def send_to_taxii(data: bytes, indicator_type):
    """ Send data to Taxii Server """

    # Create Taxii client
    client = cabby.create_client(host=TAXII_HOST,
                                 port=TAXII_PORT,
                                 discovery_path=TAXII_DISCOVERY_PATH,
                                 use_https=TAXII_USE_HTTPS,
                                 discovery_url=TAXII_DISCOVERY_URL,
                                 version=TAXII_VERSION,
                                 headers=TAXII_HEADER)

    # Set Taxii authentication
    client.set_auth(username=TAXII_USR, password=TAXII_PASS)

    # Send data
    client.push(data,
                'urn:stix.mitre.org:xml:1.1.1',
                uri='/services/inbox',
                collection_names=[map_collection(indicator_type)])


# def add_data_to_es():
#     """ Add data to ElasticSearch (used for testing) """
#
#     es = Elasticsearch([{'host': ES_HOST, 'port': ES_PORT}], http_auth=(ES_USR, ES_PASS))
#     es.create(index='threat_intelligence_type', id=51341213, body={'name': 'test 3'})
#     es.create(index='threat_intelligence_indicator', id=83456235346, body={'indicator': 'test',
#                                                                            'type_id': 51341213,
#                                                                            'content': 'test abc',
#                                                                            'title': 'test indicator',
#                                                                            'description': 'this is a test indicator',
#                                                                            'expiration': 235235235,
#                                                                            'role': 'test role',
#                                                                            'project_id': 4261246346})
#
#     es.create(index='threat_intelligence_project', id=4261246346, body={'name': 'test',
#                                                                         'description': 'this is a test project',
#                                                                         'author_name': 'Anonymous',
#                                                                         'modified': 45636436436})
#     es.close()


def map_indicator_type(type: str):
    """ Map 'custom indicator type' to 'stix indicator type' """
    if type in ANONYMIZATION:
        return IndicatorType_1_1.TERM_ANONYMIZATION
    elif type in C2:
        return IndicatorType_1_1.TERM_C2
    elif type in COMPROMISED_PKI_CERTIFICATE:
        return IndicatorType_1_1.TERM_COMPROMISED_PKI_CERTIFICATE
    elif type in DOMAIN_WATCHLIST:
        return IndicatorType_1_1.TERM_DOMAIN_WATCHLIST
    elif type in EXFILTRATION:
        return IndicatorType_1_1.TERM_EXFILTRATION
    elif type in FILE_HASH_WATCHLIST:
        return IndicatorType_1_1.TERM_FILE_HASH_WATCHLIST
    elif type in HOST_CHARACTERISTICS:
        return IndicatorType_1_1.TERM_HOST_CHARACTERISTICS
    elif type in IMEI_WATCHLIST:
        return IndicatorType_1_1.TERM_IMEI_WATCHLIST
    elif type in IMSI_WATCHLIST:
        return IndicatorType_1_1.TERM_IMSI_WATCHLIST
    elif type in IP_WATCHLIST:
        return IndicatorType_1_1.TERM_IP_WATCHLIST
    elif type in LOGIN_NAME:
        return IndicatorType_1_1.TERM_LOGIN_NAME
    elif type in MALICIOUS_EMAIL:
        return IndicatorType_1_1.TERM_MALICIOUS_EMAIL
    elif type in MALWARE_ARTIFACTS:
        return IndicatorType_1_1.TERM_MALWARE_ARTIFACTS
    elif type in URL_WATCHLIST:
        return IndicatorType_1_1.TERM_URL_WATCHLIST


def map_collection(indicator_type):
    """ Map 'indicator type' to 'collection' """
    if indicator_type in MALICIOUS_IP_COLLECTION:
        return 'Malicious_IP'
    elif indicator_type in Malicious_URL_COLLECTION:
        return 'Malicious_URL'
    elif indicator_type in MD5_HASH_COLLECTION:
        return 'MD5_Hash'
    elif indicator_type in SHA1_HASH_COLLECTION:
        return 'SHA1_Hash'
    elif indicator_type in SHA256_HASH_COLLECTION:
        return 'SHA256_Hash'
    elif indicator_type in MY_COLLECTION:
        return 'my_collection'
    else:
        return 'my_collection'


def main():
    """ Query data, parse data and send it to Taxii """

    # Query data
    data = query_es(INDICATOR_INDEX, None)

    # If any indicator ID is in the list, it means they have been added before, so we'll skip them
    existing_indicator = open('existing_indicator.txt', 'r')
    existing_id = existing_indicator.read().splitlines()
    existing_indicator.close()

    for attr in data['hits']['hits']:
        if attr['_id'] not in existing_id:
            # Init
            stix_package = STIXPackage()
            stix_header = STIXHeader()
            indicator = Indicator()
            observable = Observable()
            list_campaign = Campaigns()
            campaign = Campaign()

            # Parse data
            indicator_id = attr['_id']
            source_data = attr['_source']
            indicator_type = query_es(TYPE_INDEX, source_data['type_id'])['hits']['hits'][0]['_source']['name']
            indicator_type = map_indicator_type(indicator_type)

            project = query_es(PROJECT_INDEX, source_data['project_id'])['hits']['hits'][0]
            project_id = project['_id']
            project_name = project['_source']['name']
            project_name = Names(VocabString(project_name))
            project_description = project['_source']['description']
            project_author_name = project['_source']['author_name']

            # Data assignment
            stix_header.description = STIX_HEADER_DESCRIPTION
            observable.add_keyword(source_data['indicator'])

            indicator.id_ = indicator_id
            indicator.add_indicator_type(indicator_type)
            indicator.title = source_data['title']
            indicator.description = source_data['description']
            indicator.add_observable(observable)
            indicator.producer = project_author_name

            campaign.id_ = project_id
            campaign.description = project_description
            campaign.names = project_name
            list_campaign.campaign = campaign

            stix_package.add_indicator(indicator)
            stix_package.stix_header = stix_header
            stix_package.campaigns = list_campaign

            # Send data to Taxii
            send_to_taxii(stix_package.to_xml(), indicator_type)

            # Append id to existing_indicator file
            id_file = open('existing_indicator.txt', 'a')
            id_file.write(attr['_id'] + '\n')
            id_file.close()


main()
