# Block external IP address for Palo Alto NGFW

Response module for block external IP address for Palo Alto NGFW

# Installation

need install:
1. pan-os-python
2. thehive4py

# ToDo

to work, you need set setting PaloAltoNGFW and The Hive. If you want delete in custom Address Group you need set "Address_Group"
https://docs.paloaltonetworks.com/pan-os/8-1/pan-os-web-interface-help/monitor/monitor-block-ip-list

principle of operation:
1. the value is selected from the alert the hive.
2. ioc compare against already added AddressObject.
3. if ioc in AddressGroup, will delete
4. if ioc in AddressObject, will delete