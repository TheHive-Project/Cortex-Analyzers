# Block external IP address for Palo Alto NGFW

Response module for block external IP address for Palo Alto NGFW

# Installation

need install:
1. pan-os-python
2. thehive4py

# ToDo

to work, you need set setting PaloAltoNGFW and The Hive. If you want create or add setting for custom rule you need set "name_security_rule"

principle of operation:
1. the value is selected from the alert the hive.
2. ioc compare against already added ServiceObject.
3. if ioc not in ServiceObject, will add
4. if ioc in ServiceObject, next step
5. checks if there is already a blocking list, if not, ioc will add
6. create security rule and add ServiceGroup