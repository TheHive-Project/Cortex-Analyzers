# Thor Cortex Analyzer

The analyzer checks all hashes from the Thor report against the MISP. Use the .txt file of the report for the analyzer input.

## Installation

Add the three provided folder to the analyzer directory of the Cortex installation. 

## Configuration

Add the following configuration in the global analyzer configuration file of Cortex (usually at: /etc/cortex/application.conf). Under the point config add:

```
# Thor:
Thor {
  cortexURL = "http://localhost:9000"
  MISPSearch = "MISP_2_0"
}
```

Where the field cortexURL is the URL to the Cortex server and the MISPSearch the name of the MISP analyzer (is only tested with the version 2.0). Make sure that you also specify the version of the analyzer, otherwise cortex can't run the sub analyzer for search.