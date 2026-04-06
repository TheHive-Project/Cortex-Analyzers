# OVH Cloud Responders


## OVH Domain Order

### Description
*OVH Domain Order* can be used to purchase an **available** Domain Name with OVH Cloud registrar.  
A price limit should be set to avoid too expensive acquisitions, depending of your budget.

### Prerequisites
To use this *OVH Domain Order* Responder, you will need:
* an active OVHCloud account,
* create a OVHCloud API Keys, with necessary rights. For example:
  * post `/order/cart`
  * get `/order/cart/*`
  * post `/order/cart/*`

### Parameters

#### Price Limit
A mandatory price limit has to be set, to avoid expensive acquisitions.

> [!WARNING]
> Maximum allowed price to buy a Domain Name corresponds to the price **WITHOUT Taxes**.  
> **⚠ PRICE LIMIT USES OVH CLOUD SUBSIDIARY DEFAULT CURRENCY ⚠**

#### Required Configurations
Some Domain Name acquisition requires mandatory configuration(s), depending of the TLD or of OVH Subsidiaries.  
A list of required configurations can be found on this [OVH Cloud website](https://help.ovhcloud.com/csm/en-domain-names-api-order?id=kb_article_view&sysparm_article=KB0051563#fetch-required-configurations).

#### TheHive API
Optionally, TheHive endpoint and API Key can be set, to allow *OVH Domain Order* Responder to add tags to the Observable, even when its execution fails.

### Author
**Thales Group CERT** - [thalesgroup-cert on GitHub](https://github.com/thalesgroup-cert)


## OVH Domain Redirection

### Description
*OVH Domain Redirection* can be used to redirect an **owned** Domain Name, with OVH Cloud registrar, to the URL of your choice.  
A price limit should be set to avoid too expensive acquisitions, depending of your budget.

### Prerequisites
To use this *OVH Domain Redirection* Responder, you will need:
* an active OVHCloud account,
* create a OVHCloud API Keys, with necessary rights. For example:
  * get `/domain/zone/*`
  * post `/domain/zone/*`
  * put `/domain/zone/*`

### Parameters

#### Domain Redirection
Set the full URL where to redirect parent domain and `www` subdomain.  
  
For example:
* if domain redirection is set to `https://mydomain.com/abuse`,
* and *OVH Domain Redirection* Responder is used on Observable `myd0main.com`,
* then requests to `myd0main.com` & `www.myd0main.com` will redirect to `https://mydomain.com/abuse`.

#### TheHive API
Optionally, TheHive endpoint and API Key can be set, to allow *OVH Domain Redirection* Responder to add tags to the Observable, even when its execution fails.

### Author
**Thales Group CERT** - [thalesgroup-cert on GitHub](https://github.com/thalesgroup-cert)
