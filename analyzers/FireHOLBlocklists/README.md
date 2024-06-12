### FireJOLBlocklists
[FireJOLBlocklists](http://iplists.firehol.org/) is a composition of other IP lists.
The objective is to create a blacklist that can be safe enough to be used on all systems, with a firewall, to block access entirely, from and to its listed IPs.

The analyzer comes in a single flavout that will return if provided ip is in block list and link to its report.

#### Requirements
You need to clone original repo on the cortex machine [git clone https://github.com/firehol/blocklist-ipsets] and update relative path in `blocklistpath` variable.