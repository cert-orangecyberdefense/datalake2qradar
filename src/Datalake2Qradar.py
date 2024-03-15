import asyncio
import config
import uuid
import json
import time
import os
import re
import threading
import ipaddress
import requests
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from constants import (
    ATOM_TYPE,
    ATOM_VALUE,
    THREAT_HASHKEY,
    THREAT_SCORES,
    THREAT_TYPES,
    HASHES_MD5,
    HASHES_SHA1,
    HASHES_SHA256,
    LAST_UPDATED,
    SUBCATEGORIES,
    SOURCE_SYSTEM_NAME,
    BATCH_SIZE,
    REQUESTS_PER_MINUTE,
    CONNECTOR_CONSUMER_COUNT,
)
import requests
from datetime import datetime, timedelta
from stix2 import Indicator, exceptions
from datalake import Datalake, Output
from dotenv import load_dotenv

load_dotenv()


class QradarReference:
    def __init__(
        self,
        qradar_url: str,
        qradar_token: str,
        qradar_reference_name: str,
        qradar_ssl_verify: bool,
    ) -> None:
        self.qradar_url = qradar_url
        self.qradar_token = qradar_token
        self.qradar_reference_name = qradar_reference_name
        self.qradar_ssl_verify = qradar_ssl_verify

    @property
    def collection_url(self) -> str:
        return f"{self.qradar_url}/api/reference_data/sets/{self.qradar_reference_name}"

    @property
    def headers(self) -> dict:
        return {
            "SEC": f"{self.qradar_token}",
        }

    def init(self) -> bool:
        return True

    def get_type(self, payload):
        return re.search(r"\[(.*?):", str(payload["pattern"])).group(1)

    def create_reference(self, name: str):
        r = requests.post(
            f"{self.qradar_url}/api/reference_data/sets?element_type=ALN&name={self.qradar_reference_name}_{name}",
            headers=self.headers,
            verify=self.qradar_ssl_verify,
        )
        return r.status_code < 300

    def create(self, id: str, payload: dict):
        r = requests.post(
            f"{self.collection_url}_{self.get_type(payload)}",
            {"value": payload.get("name")},
            headers=self.headers,
            verify=self.qradar_ssl_verify,
        )
        if r.status_code == 404:
            self.create_reference(self.get_type(payload))
            self.create(id, payload)
        else:
            r.raise_for_status()

    def update(self, id: str, payload: dict):
        r = requests.post(
            f"{self.collection_url}_{self.get_type(payload)}",
            {"value": payload.get("name")},
            headers=self.headers,
            verify=self.qradar_ssl_verify,
        )
        if r.status_code == 404:
            self.create(id, payload)
        else:
            r.raise_for_status()


class Datalake2Qradar:
    """
    A class that handles all the logic of the connector: getting the iocs from
    Datalake, transform them into STIX indicator's object and send them to QRadar.
    """

    def __init__(
        self,
        qradar_reference: QradarReference,
        queue: Queue,
        consumer_count: int,
        logger,
    ):
        self.qradar_reference = qradar_reference
        self.queue = queue
        self.consumer_count = consumer_count
        self.logger = logger

    def produce_ioc(self, msg):
        while True:
            if not self.queue.full():
                self.queue.put(msg)
                return
            else:
                self.logger.debug("Queue is full, waiting...")
                time.sleep(1)

    def produce(self, indicators):
        # Produce indicators to queue
        for indicator in indicators:
            ioc = json.loads(indicator.serialize())
            self.produce_ioc({"ioc": ioc})

    def start_consumers(self):
        self.logger.info(f"starting {self.consumer_count} consumer threads")
        with ThreadPoolExecutor() as executor:
            for _ in range(self.consumer_count):
                executor.submit(self.consume)

    def start_producer(self, indicators):
        producer_thread = threading.Thread(target=self.produce, args=(indicators,))
        producer_thread.start()
        self.logger.info("starting producer thread")

    def consume(self):
        # ensure the process stop when there is an issue while
        # processing message
        try:
            self._consume()
        except Exception as e:
            self.logger.error("an error occurred while consuming messages")
            self.logger.error(e)
            os._exit(1)  # exit the current process, killing all threads

    def _consume(self):
        while True:
            msg = self.queue.get()
            payload = msg["ioc"]
            id = payload["id"]

            self.logger.debug(f"processing message with id {id}")
            self.qradar_reference.create(id, payload)
            self.logger.debug(f"reference_set item with id {id} created")

    def _getDatalakeThreats(self):
        query_fields = [
            "atom_type",
            "atom_value",
            "threat_hashkey",
            "last_updated",
            ".hashes.md5",
            ".hashes.sha1",
            ".hashes.sha256",
            "threat_scores",
        ]
        if config.add_score_labels:
            query_fields.append("threat_types")
        if config.add_threat_entities_as_labels:
            query_fields.append("subcategories")

        dtl = Datalake(
            username=os.environ["OCD_DTL_USERNAME"],
            password=os.environ["OCD_DTL_PASSWORD"],
        )
        coroutines = []

        for query in config.datalake_queries:
            self.logger.info(
                f"Creating BulkSearch for {query['query_hash']} query_hash ..."
            )

            task = dtl.BulkSearch.create_task(
                query_hash=query["query_hash"], query_fields=query_fields
            )
            coroutines.append(task.download_async(output=Output.JSON))

        loop = asyncio.get_event_loop()
        future = asyncio.gather(*coroutines)
        results = loop.run_until_complete(future)
        for result in results:
            self.logger.info(
                "Get {} threats from Datalake with {} query_hash".format(
                    result["count"], result["advanced_query_hash"]
                )
            )

        return results

    def _generateStixIndicators(self, bulk_searches_results):
        stix_indicators = []
        self.logger.info("Generating STIX indicators ...")

        for index, bulk_search_result in enumerate(bulk_searches_results):
            query_hash = bulk_search_result["advanced_query_hash"]
            input_label = config.datalake_queries[index]["label"]
            valid_until = datetime.now() + timedelta(
                hours=config.datalake_queries[index]["valid_until"]
            )

            for threat in bulk_search_result["results"]:
                try:
                    stix_indicators.append(
                        Indicator(
                            type="indicator",
                            id="indicator--{}".format(
                                uuid.uuid5(
                                    uuid.NAMESPACE_OID,
                                    query_hash + input_label + threat[THREAT_HASHKEY],
                                )
                            ),
                            name=threat[ATOM_VALUE],
                            pattern=self._create_stix_pattern(
                                threat[ATOM_VALUE],
                                threat[ATOM_TYPE],
                                threat[HASHES_MD5],
                                threat[HASHES_SHA1],
                                threat[HASHES_SHA256],
                            ),
                            pattern_type="stix",
                            valid_from=threat[LAST_UPDATED],
                            valid_until=valid_until.isoformat() + "Z",
                            labels=self._create_stix_labels(
                                input_label=input_label,
                                threat_types=threat[THREAT_TYPES]
                                if THREAT_TYPES
                                else None,
                                threat_scores=threat[THREAT_SCORES]
                                if config.add_score_labels
                                else None,
                                subcategories=threat[SUBCATEGORIES]
                                if SUBCATEGORIES
                                else None,
                            ),
                            confidence=max(threat[THREAT_SCORES]),
                            external_references=[
                                {
                                    "source_name": "Orange Cyberdefense",
                                    "url": "https://datalake.cert.orangecyberdefense.com/gui/threat/{}".format(
                                        threat[THREAT_HASHKEY]
                                    ),
                                }
                            ],
                        )
                    )
                except exceptions.InvalidValueError as e:
                    self.logger.error(
                        f"An error occured when creating stix indicator for threat {threat} : {e}"
                    )
                except Exception as e:
                    if "unknown" in str(e):
                        self.logger.error(f"{e}")

        self.logger.info("STIX indicators generated")

        return stix_indicators

    def _create_stix_pattern(
        self, atom_value, atom_type, hashes_md5, hashes_sha1, hashes_sha256
    ):
        pattern_format = "[{}:{} = {}]"

        if atom_type == "domain" or atom_type == "fqdn":
            return pattern_format.format("domain-name", "value", repr(atom_value))
        elif atom_type == "url":
            return pattern_format.format("url", "value", repr(atom_value))
        elif atom_type == "email":
            return pattern_format.format("email-addr", "value", repr(atom_value))
        elif atom_type == "ip":
            try:
                if isinstance(ipaddress.ip_address(atom_value), ipaddress.IPv4Address):
                    return pattern_format.format("ipv4-addr", "value", repr(atom_value))
                elif isinstance(
                    ipaddress.ip_address(atom_value), ipaddress.IPv6Address
                ):
                    return pattern_format.format("ipv6-addr", "value", repr(atom_value))
            except ValueError:
                pass
        elif atom_type == "file":
            conditions = []

            if hashes_md5:
                conditions.append(f"file:hashes.MD5 = '{hashes_md5}'")
            if hashes_sha1:
                conditions.append(f"file:hashes.SHA1 = '{hashes_sha1}'")
            if hashes_sha256:
                conditions.append(f"file:hashes.SHA256 = '{hashes_sha256}'")
            if not conditions:
                return None

            pattern = " OR ".join(conditions)
            return f"[{pattern}]"

        else:
            raise Exception(f"Atom type '{atom_type}' is unknown or is not handle")

    def _create_stix_labels(
        self, input_label, threat_types, threat_scores, subcategories
    ):
        stix_labels = [input_label]

        if subcategories:
            for subcategory in subcategories:
                stix_labels.append(subcategory)

        if threat_types:
            max_score = max(threat_scores) - (max(threat_scores) % 10)
            max_score = max_score if max_score < 100 else 90
            stix_labels.append("dtl_score_" + str(max_score))

            for index, threat_type in enumerate(threat_types):
                stix_labels.append(
                    "dtl_score_{}_{}".format(
                        threat_type, threat_scores[index] - (threat_scores[index] % 10)
                    )
                )

        return stix_labels

    def start(self):
        if self.qradar_reference.init():
            self.logger.info("reference_set created")
        else:
            self.logger.warning("unable to create reference_set")

        self.start_consumers()

    def uploadIndicatorsToQradar(self):
        bulk_searches_results = self._getDatalakeThreats()
        indicators = self._generateStixIndicators(bulk_searches_results)

        # Start producer
        self.start_producer(indicators)

        # Start consumers
        self.start()

        return
