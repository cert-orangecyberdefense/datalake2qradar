# Datalake to QRadar SIEM connector

## About the Connector

The Datalake to QRadar SIEM connector allows you to ingest **threat indicators (IOCs)** from Orange Cyberdefense Datalake Platform to QRadar SIEM solution.

## Getting Started

### Prerequisites

First of all, you need to have a **Datalake account**. If so, follow the steps below if you want to run the **datalake2qradar** connector in a dedicate server.

* Rename the file `config.py.default` to `config.py` and adapt the values according to your usage. This file is use to configure the **Datalake API requests** which will be executed and the **behavior** of the Datalake2Qradar connector.
* Rename the file `.env.default` to `.env` and replace the environment variables with yours. This file is use to define all the credentials for **Datalake API** and **QRadar**.
* Create a token **datalake2qradarconnector** in qradar. You can follow this documentation [create-authentification-token](https://www.ibm.com/docs/en/qradar-common?topic=forwarding-creating-authentication-token)


### Usage