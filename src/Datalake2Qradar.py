import asyncio
import config
import time
import os
import threading
import requests
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from constants import ATOM_TYPE, ATOM_VALUE, SOURCE_SYSTEM_NAME
import requests
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
        logger,
    ) -> None:
        self.qradar_url = qradar_url
        self.qradar_token = qradar_token
        self.qradar_reference_name = qradar_reference_name
        self.qradar_ssl_verify = qradar_ssl_verify
        self.logger = logger

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
        return payload[ATOM_TYPE]

    def create_reference(self, name: str):
        r = requests.post(
            f"{self.qradar_url}/api/reference_data/sets?element_type=ALN&name={self.qradar_reference_name}_{name}",
            headers=self.headers,
            verify=self.qradar_ssl_verify,
        )
        return r.status_code < 300
    
    def get_all_reference_sets(self):
        r = requests.get(
            f"{self.qradar_url}/api/reference_data/sets",
            headers=self.headers,
            verify=self.qradar_ssl_verify,
        )

        reference_sets_datalake = set()

        if r.status_code == 200:
            reference_sets = r.json()
            for ref_set in reference_sets:
                if re.match(r"^datalake_[A-Za-z]+$", ref_set["name"]):
                    reference_sets_datalake.add(ref_set["name"])

            return reference_sets_datalake
        else:
            r.raise_for_status()

    def get_reference_sets_data(self):
        reference_sets_data = []
        reference_sets = self.get_all_reference_sets()

        for ref in reference_sets:
            r = requests.get(
                f"{self.qradar_url}/api/reference_data/sets/{ref}",
                headers=self.headers,
                verify=self.qradar_ssl_verify,
            )

            if r.status_code == 200:
                reference_type = re.search(r"datalake_([a-zA-Z0-9]+)", ref).group(1)
                if "data" in r.json():
                    data = r.json()["data"] 
                    for ioc in data:
                        reference_sets_data.append([reference_type, ioc["value"]])
            else:
                self.logger.debug(f"reference set {ref} does not exist")

        return reference_sets_data
                

    def create(self, id: str, payload):
        r = requests.post(
            f"{self.collection_url}_{self.get_type(payload)}",
            {"value": payload[ATOM_VALUE], "source": SOURCE_SYSTEM_NAME},
            headers=self.headers,
            verify=self.qradar_ssl_verify,
        )
        if r.status_code == 404:
            self.create_reference(self.get_type(payload))
            self.create(id, payload)
        elif r.status_code == 200:
            self.logger.debug(f"{payload[ATOM_VALUE]} created")
        else:
            self.logger.error(f"Error {r.status_code} during creation of {payload[ATOM_VALUE]}")

    def delete(self, id: str, payload):
        encoded_value = urllib.parse.quote(payload[ATOM_VALUE], safe='')
        double_encoded_value = urllib.parse.quote(encoded_value, safe='')

        r = requests.delete(
            f"{self.collection_url}_{self.get_type(payload)}/{double_encoded_value}",
            headers=self.headers,
            verify=self.qradar_ssl_verify,
        )
        if r.status_code == 200:
            self.logger.debug(f"{payload[ATOM_VALUE]} deleted")
        else:
            self.logger.error(f"Error {r.status_code} during deletion of {payload[ATOM_VALUE]}")


class Datalake2Qradar:
    """
    A class that handles all the logic of the connector: getting the iocs from
    Datalake and send them to QRadar.
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

    def produce(self, messages):
        # Produce indicators to queue
        for message in messages:
            if message["indicators"]:
                for indicator in message["indicators"]:
                    self.produce_ioc({"action": message["action"], "ioc": indicator})

    def start_consumers(self):
        self.logger.info(f"starting {self.consumer_count} consumer threads")
        with ThreadPoolExecutor() as executor:
            for _ in range(self.consumer_count):
                executor.submit(self.consume)

    def start_producer(self, messages):
        producer_thread = threading.Thread(target=self.produce, args=(messages,))
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
            action = msg["action"]
            atom_value = payload[ATOM_VALUE]

            if action == "add":
                self.qradar_reference.create(id, payload)
            elif action == "delete":
                self.qradar_reference.delete(id, payload)
            

    def _getDatalakeThreats(self):
        query_fields = ["atom_type", "atom_value"]

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

    def start(self):
        if self.qradar_reference.init():
            self.logger.info("reference_set created")
        else:
            self.logger.warning("unable to create reference_set")

        self.start_consumers()

    def _generateIndicators(self, bulk_searches_results):
        self.logger.info("Generating indicators ...")
        indicators = []

        for bulk_search_result in bulk_searches_results:
            indicators.extend(bulk_search_result["results"])

        self.logger.info("Indicators generated")

        return indicators
    
    def diff_indicators(self, bulk_searches_results):

        reference_sets_indicators = self.qradar_reference.get_reference_sets_data()
        indicators = self._generateIndicators(bulk_searches_results)
        
        indicators_tuple = []
        reference_sets_indicators_tuple = []

        for ioc in indicators:
            indicators_tuple.append(tuple(ioc))

        if reference_sets_indicators:
            for ioc in reference_sets_indicators:
                reference_sets_indicators_tuple.append(tuple(ioc))

            added_indicators = set(indicators_tuple) - set(reference_sets_indicators_tuple)
            removed_indicators = set(reference_sets_indicators_tuple) - set(indicators_tuple)

            return [
                {
                    "action": "add",
                    "indicators": added_indicators
                },
                {
                    "action": "delete",
                    "indicators": removed_indicators
                }
            ]
        
        else:
            return [
                {
                    "action": "add",
                    "indicators": indicators
                }
            ]




    def uploadIndicatorsToQradar(self):
        bulk_searches_results = self._getDatalakeThreats()
        messages = self.diff_indicators(bulk_searches_results)
        # Start producer
        self.start_producer(messages)

        # Start consumers
        self.start()

        return
