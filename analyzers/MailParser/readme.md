# MailParser Cortex Analyzer

The MailParser uses the old MsgParser to parse an E-Mail observable. Also the analyzer queries the file info analyzer to get information about the attached files and gets all URL indicator out of the body. For all observables the MISP search analyzer is queried. If the MISP analyzer finds an event with the observale it will be displayed in red and with a click on it you can see a list with the correlated events. With a click on the event it is opened in the MISP.

## Installation

Add the three provided folder to the analyzer directory of the Cortex installation. 

## Configuration

Add the following configuration in the global analyzer configuration file of Cortex (usually at: /etc/cortex/application.conf). Add the following as a child of the config tag:

```
# MailParser:
MailParser {
  cortexURL = "http://localhost:9000"
  fileInfo = "File_Info_2_0"
  MISPSearch = "MISP_2_0"
}
```

Where the cortexURL is the URL to the Cortex server, the fileInfo the name of the file info analyzer (is only tested with the version 2.0) and the MISPSearch the name of the MISP analyzer (is only tested with the version 2.0). Make sure that you also specify the version of the analyzer, otherwise cortex can't run the sub analyzer for search and file info for the attachments.