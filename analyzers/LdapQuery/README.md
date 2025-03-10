### Description
LDAP Query analyzer will request LDAP server to provide information about organisation's users, from observable of type ```mail``` or ```username```.

### How it works
The analyzer is launch from an observable. The data (value) of this observable is used to request the LDAP server.  
Optionally, from ```LdapQuery 3.0```, you can:
* define **whitelists** to prevent undesirable requests to the LDAP server, using a specific username format for instance,
* define which attributes you want to import as **Observables**,
* define which attributes you want to import as **Tags**,
* define which attributes you want to import as **Custom Fields**.


### Reports' summary
Every time the analyzer is run, it should provide a report's summary attached to its observable. This summary is using a color code to quickly identify the result: blue, yellow or red.

#### Request success
Success requests are displayed with blue color (```LDAP:Query=John DOE```).  
It means that the request has been sent to the LDAP server, and that a user has been found. By clicking on the report, relevant information can be quickly displayed by apadting provided long template.

#### Request filtered
Filtered requests are displayed with yellow color (```LDAP:Query=filtered```).  
It means that the observable data has been filtered, so no request has been sent to the LDAP server.
By clicking on the report, whitelisted RegEx of allowed email domain name / username format is display. It can help you understand why the data has been filtered, in order to update your whitelist(s) or not.

#### Request no result
Requests returning no result are displayed with red color (```LDAP:Query=no_result```).  
It means that the request has been sent to the LDAP server, but no corresponding user has been found. Reason could be that given data are not accurate or non-existing.


### Whitelists
By default, no whitelist are set, meaning that no filters are applied.

#### Whitelist for type ```mail```
For observable of type ```mail```, the whitelist is based on email's domain name. The code will simply split the email address at char ```@```, and check if the domain name is in the whitelist or not.


If the domain name is not in the whitelist, the request will be *filtered*. When clicking on report's summary, whitelist can be display to check what is whitelisted or not. This can help you to populate the whitelist. 

#### Whitelist for type ```username ```
For observable of type ```username ```, the whitelist is based on regular expression comparison. The code will simply check if the username match any regular expression which are  in the whitelist.


If regular expressions don't match the username, the request will be *filtered*. When clicking on report's summary, whitelisted regular expressions can be display to check for a better understanding. This can help you to populate the whitelist. 


### Attributes importation
To import an attribute, it is mandatory to add it first to the list of attributes you want to harvest (parameter `attributes`).

#### Import as Observables
Parameter `attributes_to_extract` allow to specify which attributes you want to extract as **Observables**. To import it with the appropriate type, you need to map the attibute name and the observable type, by using `:` separator:
* Format: `attribute:datatype` (attributes need to respect case sensivity),
* Examples:
  * `uid:username` will import found `uid` attribute(s) into Observable(s) of type `username`,
  * `mail:mail` will import found `mail` attribute(s) into Observable(s) of type `mail`. When attributes and type are the same, `mail` or `mail:` will provide the same result than `mail:mail`.

#### Import as Tags
Parameter `attributes_to_tags` allow to specify which attributes you want to extract as Observable's **Tags**. To customize tags' prefix, you can map the attibute name and the desired prefix, by using `:` separator:
* Format: `attribute` or `attribute:prefix` (attributes need to respect case sensivity),
* Examples:
  * `mail` will add the tag `mail:jdoe@domain.org`,
  * `mail:e-mail` will add the tag `e-mail:jdoe@domain.org`.

#### Import as Custom Fields
Parameter `attributes_to_tags` allow to specify which attributes you want to extract as **Custom Fields**. To choose which Custom Field to populate, you can map attibutes name and Custom Field names, by using `:` separator:
* Format: `attribute` or `attribute:custom_field_name` (attributes need to respect case sensivity),
* Example: if 'c' value is 'France' in the LDAP response, `c:country` will add the entry `France` in `country` Custom Field.

### TheHive template
A template for TheHive (`long.html`) comes along this new version.  
This template dynamically adapts to LDAP query results, automatically displaying all attributes harvested.
* Prioritizes Full Name, Email, and UID, while listing other attributes dynamically
* Limits output to 5 results for clarity
* Handles filtered results, errors, and empty responses
