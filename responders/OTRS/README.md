#### OTRS Responder

Summary: Creates OTRS tickets from TheHive

Applies To: Cases

##### Prerequisites

Python: see requirements.txt
OTRS: a Web Services named `GenericTicketConnectorREST`

##### Initial Responder Configuration

The following need to be configured under **Organization --> Responders** prior to use:

`otrs_username` - **Required** - Username to log into OTRS
`otrs_password` - **Required** - Password to log into OTRS
`otrs_url` - **Required** - : URL pointing to OTRS installation, e.g. `https://otrs.example.com`
`otrs_queue` - **Required** - Queue for OTRS tickets, e.g. `SOC`
`otrs_ticket_type` - **Required** - OTRS ticket type, e.g. `SecurityIncident`
`otrs_communication_channel` - **Required** - OTRS communication channel, e.g. `Email` or `OTRS`
`otrs_dynamic_fields` - Dynamic field key and value separated by colon, e.g. `Competence:The Hive`
`customer_table` - **Required** - Lookup table for tag and OTRS customers separated by colon, e.g. `customer:soc@customer.com`
`thehive_url` - **Required** - URL pointing to your TheHive installation, e.g. `http://thehive.example.com`
`thehive_apikey` - **Required** - TheHive API key which is used to add the downloaded file back to the alert/case 

##### Workflow

1. The responder lookup for the OTRS customer, based on the TheHive case tags (see `customer_table`)
2. An OTRS ticket is created using the title and the description from the TheHive case. The Url pointing to TheHive case is prepended to the OTRS article.
3. The Url pointing to the OTRS ticket is prepended to TheHive case.
4. The responder fails if it called more than once. To force that, the OTRS related data must be deleted from the TheHive case description.
