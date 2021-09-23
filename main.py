import cabby

import datetime
from dateutil import tz

from stix.core import STIXPackage, STIXHeader, Campaigns
from stix.indicator import Indicator
from stix.common.vocabs import VocabString
from stix.campaign import Campaign, Names

from cybox.utils import Namespace
from cybox.core import Observable

from mixbox.idgen import set_id_namespace
from elasticsearch import Elasticsearch

from consts import *

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
            indicator_data = attr['_source']
            indicator_type = query_es(TYPE_INDEX, indicator_data['type_id'])['hits']['hits'][0]['_source']['name']

            project = query_es(PROJECT_INDEX, indicator_data['project_id'])['hits']['hits'][0]
            project_id = project['_id']
            project_name = project['_source']['name']
            project_name = Names(VocabString(project_name))
            project_description = project['_source']['description']
            project_author_name = project['_source']['author_name']

            # Data assignment
            stix_header.description = STIX_HEADER_DESCRIPTION

            observable.add_keyword(indicator_data['indicator'])

            indicator.id_ = indicator_id
            indicator.add_indicator_type(VocabString(indicator_type))
            indicator.title = indicator_data['title']
            indicator.description = indicator_data['description']
            indicator.producer = project_author_name
            indicator.add_observable(observable)

            campaign.id_ = project_id
            campaign.description = project_description
            campaign.names = project_name

            list_campaign.campaign = campaign

            stix_package.add_indicator(indicator)
            stix_package.stix_header = stix_header
            stix_package.campaigns = list_campaign

            # Add timestamp
            tz_info = tz.gettz(TIMEZONE)
            stix_package.timestamp = datetime.datetime.now().astimezone(tz=tz_info)

            # Send data to Taxii
            send_to_taxii(stix_package.to_xml(), indicator_type)

            # Print log
            print("[" + str(stix_package.timestamp) + "] Successfully added \"" +
                  str(stix_package.id_) + "\" to Taxii Server")

            # Append id to existing_indicator file
            id_file = open('existing_indicator.txt', 'a')
            id_file.write(attr['_id'] + '\n')
            id_file.close()


main()
