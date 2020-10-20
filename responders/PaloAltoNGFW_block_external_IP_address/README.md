# Block external IP address for Palo Alto NGFW

Response module for block external IP address for Palo Alto NGFW

# Installation

need install:
1. pan-os-python
2. thehive4py

# ToDo

to work, you need to create Address_Group in PaloAltoNGFW and create security polites and name them in  "name_external_Address_Group".
https://docs.paloaltonetworks.com/pan-os/8-1/pan-os-web-interface-help/monitor/monitor-block-ip-list

principle of operation:
1. the value is selected from the alert the hive.
2. ioc compare against already added AddressObject.
3. if ioc not in AddressObject, will add
4. if ioc in AddressObject, next step
5. checks if there is already a blocking list, if not, ioc will add