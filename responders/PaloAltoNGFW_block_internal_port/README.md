# Block external IP address for Palo Alto NGFW

Response module for block external IP address for Palo Alto NGFW

# Installation

need install:
1. pan-os-python
2. thehive4py

# ToDo

to work, you need to create Address_Group in PaloAltoNGFW and create security polites and name them in  "name_internal_Service_Group".

First: you need add field "port" and "protocol" to "Observable types management" in the hive.
or you can change script and call your field names

principle of operation:
1. the value is selected from the alert the hive.
2. ioc compare against already added Service_Group.
3. if ioc not in Service_Group, will add field port and protocol
4. if ioc in Service_Group, next step
5. checks if there is already a blocking list, if not, ioc will add