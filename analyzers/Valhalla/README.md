### Valhalla

The Valhalla analyzer queries the Valhalla YARA rule databased and retrieves the matching YARA rules.

#### Requirements

- [ValhallaAPI](https://github.com/NextronSystems/valhallaAPI)

#### Scope

The result contains all matching YARA rules including

- Nextron's rules in the [public rule repository](https://github.com/Neo23x0/signature-base/)
- Nextron's rules sold in the form of the [YARA rule feed](https://www.nextron-systems.com/valhalla/)

The result does not contain matches with YARA rules

- submitted by 3rd parties into the [public rule repository](https://github.com/Neo23x0/signature-base/) due to legal restrictions
- rules that are tagged as confidential and can therefore only be used in Nextron's scanner [THOR](https://www.nextron-systems.com/thor/)
- rules that require external variables and can therefore only be used in Nextron's scanner [THOR](https://www.nextron-systems.com/thor/)

The database contains YARA rule matches on samples submitted to Virustotal and Nextron's internal sample matching, which accounts for less than 1% of the matches within that database. The database does not contain information on samples that have not been transmitted to Virustotal.

#### Matches

The matches in the long report link to rule info pages that contain more information, like other matching samples, a report or public source in which the sample from which that rule was derived has been mentioned.

They also include the Antivirus detection rate at the moment of the first submission to Virustotal, which gives a good indication of the overall coverage.
