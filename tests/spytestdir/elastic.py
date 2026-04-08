#typical Elastic client setup 
#From a security point of view: Data exfiltration to an external provider with too many risks.

import os
from elasticsearch import Elasticsearch

def main():
    client = Elasticsearch(
        hosts=[os.getenv("ELASTICSEARCH_URL")],
        api_key=os.getenv("ELASTIC_API_KEY"),
    )

    resp = client.search(
        index="my-index-000001",
        from_=40,
        size=20,
        query={
            "term": {
                "user.id": "kimchy"
            }
        },
    )
    print(resp)