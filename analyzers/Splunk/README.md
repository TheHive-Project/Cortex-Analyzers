This analyzer allows you to execute a list of searches in Splunk by passing the element you are looking for as a parameter

This analyzer comes in 10 flavors:

- Splunk_Search_**Domain_FQDN**: Dispatch a list of saved searches on a given domain/fqdn
- Splunk_Search_**File_Filename**: Dispatch a list of saved searches on a given file/filename
- Splunk_Search_**Hash**: Dispatch a list of saved searches on a given hash
- Splunk_Search_**IP**: Dispatch a list of saved searches on a given IP (IPv4 only)
- Splunk_Search_**Mail_Email**: Dispatch a list of saved searches on a given mail/email
- Splunk_Search_**Mail_Subject**: Dispatch a list of saved searches on a given mail_subject
- Splunk_Search_**Other**: Dispatch a list of saved searches on a given data (any type)
- Splunk_Search_**Registry**: Dispatch a list of saved searches on a given registry
- Splunk_Search_**URL_URI_Path**: Dispatch a list of saved searches on a given url/uri_path
- Splunk_Search_**User_Agent**: Dispatch a list of saved searches on a given user_agent
- Splunk_Search_**User**: Dispatch a list of saved searches on a given user id (variable name is 'other'

#### Requirements

You need to have access to a Splunk instance with a dedicated account. For any saved search you want to use, you have to group them in the same Application and with the same owner.
When you configure an analyzer, it will ask you these information:

- **host**: This is the domain name or the IP of your Splunk instance.
- **port**: This is the port to reach to access Splunk (API) (Splunk default to 8089).
- **port_gui**: This is the port to reach to access Splunk (HTTP) (Splunk default to 8000).
- **username** (optional): If your Splunk instance has authentication, you need an account to access to it (and to the indexes you want to search). Please avoid to use admin. 
- **password** (optional): If your Splunk instance has authentication, this is the password of the previous account. Please avoid to use admin and respect password complexity. No token access is supported.
- **application**: This is the application in which all the saved searches are stored on your Splunk instance.
- **owner**: This is the owner of all the saved searches, it must be the same for all of them. This can be different from the username mentionned above but you will need shared rights.
- **savedsearches**: A list of all saved searches you want to execute. You just have to put the name of the saved searches here. **Each saved search will be executed/dispatch in parallel (and so they will become jobs)  but the Cortex job will finish once all Splunk jobs are done**.
- **earliest_time**: If not empty, this parameter will specify the earliest time to use for all searches. If empty, the earliest time set in the saved search will be used by Splunk 
- **latest_time**: If not empty, this parameter will specify the latest time to use for all searches. If empty, the latest time set in the saved search will be used by Splunk 
- **max_count**: This parameter is set to 1,000 by default. It's the number of results to recover from the job. A limit is set to avoid any trouble in TheHive/Cortex on the GUI. If value is set to 0, then all available results are returned.

#### How to recover arguments in Splunk ?

All arguments can be retrieve using "$args.DATATYPE$". As an example is better than a long speech, here it is:

Imagine that you have a search with this query:

```
index=myindex_internet sourcetype=mysourcetype url=$args.url$*
| stats count by user, url, src_ip
```

This query will recover the data using $args.url$.

So, you can recover your data using :

- $args.type$: This parameter indicates the type of data (if you need so)
- $args.domain$: This parameter contains the data for an analysis over a domain
- $args.fqdn$: This parameter contains the data for an analysis over a fqdn
- $args.file$: This parameter contains the data for an analysis over a file
- $args.filename$: This parameter contains the data for an analysis over a filename
- $args.hash$: This parameter contains the data for an analysis over a hash
- $args.ip$: This parameter contains the data for an analysis over a ip
- $args.mail$: This parameter contains the data for an analysis over a mail
- $args.email$: This parameter contains the data for an analysis over a email
- $args.mail_subject$: This parameter contains the data for an analysis over a email_subject
- $args.other$: This parameter contains the data for an analysis over a other
- $args.registry$: This parameter contains the data for an analysis over a registry
- $args.url$: This parameter contains the data for an analysis over a url
- $args.uri_path$: This parameter contains the data for an analysis over a uri_path
- $args.user-agent$: This parameter contains the data for an analysis over a user-agent

#### Taxonomies

They are 5 taxonomies available on this analyzer:

- **Splunk:Results**: Indicates the total number of results found by all the saved searches
- **Splunk:Info** (optional): Indicates the total number of results which have a field "level" set to "info"
- **Splunk:Safe** (optional): Indicates the total number of results which have a field "level" set to "safe"
- **Splunk:Suspicious** (optional): Indicates the total number of results which have a field "level" set to "suspicious"
- **Splunk:Malicious** (optional): Indicates the total number of results which have a field "level" set to "malicious"

As mentionned above, your saved searches can return a field named "level" which will be interpreted by Cortex/TheHive as a taxonomy and will create reports accordingly to the value (info,safe,suspicious or malicious)
