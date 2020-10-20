# Block external IP address for Palo Alto NGFW

Response module for block external IP address for Palo Alto NGFW

# Installation

need install:
1. pan-os-python
2. thehive4py

# ToDo

to work, you need to create Address_Group in PaloAltoNGFW and create security polites and name them in  "name_internal_Service_Group" and "name_external_Service_Group".


principle of operation:
1. the value is selected from the alert the hive.
2. if ioc added in Service_Groups, script deleted ioc
3. if ioc in AddressObject, script deleted ioc