# Datalake to QRadar SIEM connector

## About the Connector

The Datalake to QRadar SIEM connector allows you to ingest **threat indicators (IOCs)** from Orange Cyberdefense Datalake Platform to QRadar SIEM solution.

## Getting Started

### Prerequisites

First of all, you need to have a **Datalake account**. If so, follow the steps below if you want to run the **datalake2qradar** connector in a dedicated server.

* Rename the file `config.py.default` to `config.py` and adapt the values according to your usage. This file is used to configure the **Datalake API requests** which will be executed and the **behavior** of the Datalake2Qradar connector.
* Rename the file `.env.default` to `.env` and replace the environment variables with yours. This file is used to define all the credentials for the **Datalake API** and **QRadar**.
* Create a token **datalake2qradarconnector** in QRadar. You can follow this documentation [create-authentification-token](https://www.ibm.com/docs/en/qradar-common?topic=forwarding-creating-authentication-token)


### Usage
To launch the connector execute the CLI command `docker compose up -d`, you can then see the logs with the CLI command `docker compose logs -f datalake2qradar`. 


## Testing the connector locally

For development and testing, you can get the QRadar Community Edition from the official IBM Website : [QRadar Community Edition](https://www.ibm.com/community/101/qradar/ce/)
- Set the `QRADAR_URL` environment variable to your local QRadar url.
- If you want to launch the datalake queries immediatly for testing, don't forget to set `run_as_cron = False` in `config.py`.
- Launch the connector with `docker compose up --build`.
