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
2. user compare against already added in security rules.
3. if user in security rules, will delete