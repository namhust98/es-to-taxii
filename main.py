import cabby
import sys
import consts
from elasticsearch import Elasticsearch
import time


# Create Taxii client and connect to Taxii Server
def connect_to_taxii():
    """ Create Taxii client """
    cl = cabby.create_client(host=consts.TAXII_HOST,
                             port=consts.TAXII_PORT,
                             discovery_path=consts.TAXII_DISCOVERY_PATH,
                             use_https=consts.TAXII_USE_HTTPS,
                             discovery_url=consts.TAXII_DISCOVERY_URL,
                             version=consts.TAXII_VERSION,
                             headers=consts.TAXII_HEADER)
    return cl


def connect_to_es():
    es = Elasticsearch([{'host': consts.ES_HOST, 'port': consts.ES_PORT}])
    # es.create(index="test", id=int(round(time.time())), body={"content": "One more fox"})
    print(es.search(index="test"))
    # es.delete(index="test", id="1631514419.5779335")
    # print(es.search(index="test", doc_type="articles"))


def main():
    # services = connect_to_taxii().discover_services()
    # for service in services:
    #     print('Service type={s.type}, address={s.address}'
    #           .format(s=service))
    connect_to_es()


main()
