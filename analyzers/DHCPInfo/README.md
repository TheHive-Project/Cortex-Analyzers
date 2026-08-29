# DHCP scope analyzer

Find which subnet a local IP address belongs to.


## Rationale

When you have multiple subnets on an internal network, the particular
subnet someone is on may convey some information, like where someone
is in a building. If you have an IP observable containing a user's
workstation IP address, and an incident is going on, you want to pull
in that extra information without having to think about it. This
analyzer does that for you.


## Scope information

Put your DHCP scope information in CSV files (see examples in sources
directory). Set the configuration item `dhcp_info_directory` to the
location of the directory with the CSV files in it.

In particular, if you use Microsoft DHCP, you can directly use
exported DHCP scope information. Just save it to a CSV file like so:

```
    Get-DhcpServerv4Scope -ComputerName mydc.example.com |
       Export-CSV mydc.csv
```
