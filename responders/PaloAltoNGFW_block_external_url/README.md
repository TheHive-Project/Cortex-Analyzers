# Block external IP address for Palo Alto NGFW

Response module for block external IP address for Palo Alto NGFW

# Installation

need install:
1. pan-os-python
2. thehive4py

# ToDo

to work, you need to create Address_Group in PaloAltoNGFW and create security polites and name them in  "name_external_URL_category".


principle of operation:
1. the value is selected from the alert the hive.
2. ioc compare against already added URL_category.
3. checks if there is already a blocking list, if not, ioc will add