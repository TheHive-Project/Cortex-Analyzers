#Analyzer Goals
PLEASE NOTE: This is considered an alpha build. So use at your own risk! Limited flexibility is available in this analyzer

This analyzer is developed to find IOC's (from MISP) in QRadar data. There were a few design goals:
- It must be able to 
	- Perform a lot of queries in a small timeframe
	- Perform recurring searches on a daily basis
	- Keep the results in context with the event from which the IOC's originate
	
The results of this are an analyzer and a supporting script. The supporting script is built to perform the tasks for recurring searches to be executed and performed against a cached search for seemingly better performance.

Script functionality summarized:
- Build searches containing hits on the reference sets (defined below)
	- Create tmp files with the generated searches
- Trigger analyzer searches within The Hive for observable that are "marked" for reoccurring searches
	- Create a new task in the corresponding case when a hit is found
- Additional feature: Provide reports based on API content or AQL queries

#Configuration
###The Hive Configuration
Create the following custom fields:
- firstSearched
- lastSearched

###Cortex configuration
Configure the required within Cortex Analyzer Configuration for IBM QRadar Search.

##QRadar configuration:
NOTE: When searching for observables it is very beneficial to enable indexing for these properties. This will reduce a search to seconds instead of minutes

- Create a authorized service account with a role that has the following rights
	- Log Activity
		- Manage Time Series
	- Network Activity
		- Manage Time Series
	Delegated Administration
		- Manage Reference Data
	
Due to a bug in QRadar it might be that the user needs more rights. In that case the role unfortunately must be assigned with "System Administrator". This is only required if authorization errors are given

### Scheduled recurring searches
If you want to use automated recurring searches you will have to create the following reference sets
- qthi-domain
- qthi-fqdn
- qthi-hash-md5
- qthi-hash-sha1
- qthi-hash-sha2
- qthi-ip
- qthi-mail
- qthi-url

These get filled automatically by the plug-in. If you then schedule a search for these reference sets with the right queries, these searches are used to speed up the observable searches.
A seperate script is used for these tasks of which different actions can be scheduled through cron.

This script saves the id's for the search in a predefined file in /tmp: /tmp/<refset name>-uuid_work_file.txt
Therefore in this current set-up it is required to run the script on the same system as where the analyzer is fired.


##Basic configuration:
The following settings are available for the script. 
QRadar:
	proxies: << Use this for any proxy url's required
		http:
		https:
    url: https://<ip/hostname>:<port> << QRadar url
    key: <key> << QRadar API key. This can be the same as the key for the analyzer
    verify: <True/False/pathtocert> << Defines whether or not certificate hostname validation is enabled. Provide a path to a CA file if you have a specific file with authorized CA's
    enabled_datatypes: << Allows you to enable/disable certain datatypes.
        - ip
        - domain
        - fqdn
        - url
        - hash
    search_limit : 1 << The amount of days it searches back in time
    search_timeout : 86400 << The maximum duration it may take to complete the search
    polling_interval : 10 << polling interval for the search status
    url_root_domain_field: <field> << Field names
    url_fqdn_field:<field>
    url_field: <field>
    mail_recipient_field: <field>
    mail_sender_field: <field>
    mail_send_qid: <qid>
    mail_receive_qid: <qid>
    hash_md5: <field>
    hash_sha1: <field>
    hash_sha256: <field>
TheHive:
    proxies: << Use this for any proxy url's required
      http: 
      https: 
    url: https://<ip/hostname> << The Hive url
    key: <key> << The Hive API key
    verify: <True/False/pathtocert> << Defines whether or not certificate hostname validation is enabled. Provide a path to a CA file if you have a specific file with authorized CA's

##To test the analyzer from cmdline:
python IBMQRadar_Search.py < input