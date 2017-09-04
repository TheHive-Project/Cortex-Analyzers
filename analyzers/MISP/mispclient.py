#!/usr/bin/env python
import pymisp
import os


class EmptySearchtermError(Exception):
    """Exception raised, when no search terms are given."""
    pass


class MISPClient:
    """The MISPClient class just hides the "complexity" of the queries. All params can be lists to query more than one
    MISP instance.

    :param url: URL of MISP instance
    :type url: [str, list]
    :param key: API key
    :type key: [str, list]
    :param ssl: Use/dont' use ssl or path to ssl cert if not possible to verify through trusted CAs
    :type ssl: [bool, list, str]
    :param name: Name of the MISP instance, is sent back in the report for matching the results.
    :type name: [str, list]
    """

    def __init__(self, url, key, ssl=True, name='Unnamed'):
        self.misp_connections = []
        if type(url) is list:
            for idx, server in enumerate(url):
                verify = True
                if isinstance(ssl, list):
                    if os.path.isfile(ssl[idx]):
                        verify = ssl[idx]
                elif isinstance(ssl, str):
                    if os.path.isfile(ssl):
                        verify = ssl
                elif isinstance(ssl, bool):
                    verify = ssl
                self.misp_connections.append(pymisp.PyMISP(url=server,
                                                           key=key[idx],
                                                           ssl=verify))
        else:
            verify = True
            if os.path.isfile(ssl):
                verify = ssl
            self.misp_connections.append(pymisp.PyMISP(url=url,
                                                       key=key,
                                                       ssl=verify))
        self.misp_name = name

    @staticmethod
    def __misphashtypes():
        """Just for better readability, all __misp*type methods return just a list of misp data types

        :returns: MISP hash data types
        :rtype: list
        """
        hashtypes = ['md5', 'sha1', 'sha256', 'ssdeep', 'sha224', 'sha384', 'sha512', 'sha512/224', 'sha512/256',
                     'tlsh', 'authentihash']
        filenames = []
        for h in hashtypes:
            filenames.append('filename|{0}'.format(h))
        return hashtypes + filenames

    @staticmethod
    def __mispurltypes():
        """Just for better readability, all __misp*type methods return just a list of misp data types

        :returns: misp url/domain data types
        :rtype: list
        """
        return ['domain', 'domain|ip', 'url', 'link', 'named pipe', 'uri']

    @staticmethod
    def __mispdomaintypes():
        """Just for better readability, all __misp*type methods return just a list of misp data types

        :returns: data types containing domains
        :rtype: list
        """
        return ['domain', 'hostname', 'domain|ip', 'email-src', 'email-dst', 'url', 'link', 'named pipe',
                'target-email', 'uri', 'whois-registrant-email', 'dns-soa-email', 'hostname|port', 'jabber-id']

    @staticmethod
    def __mispmailtypes():
        """Just for better readability, all __misp*type methods return just a list of misp data types

        :returns: misp mail data types
        :rtype: list
        """
        return ['email-src', 'email-dst', 'target-email', 'email-subject', 'email-attachment', 'whois-registrant-email',
                'dns-soa-email', 'email-header']

    @staticmethod
    def __mispiptypes():
        """Just for better readability, all __misp*type methods return just a list of misp data types

        :returns: ip data types
        :rtype: list
        """
        return ['ip-src', 'ip-dst', 'domain|ip', 'ip-src|port', 'ip-dst|port']

    @staticmethod
    def __mispregistrytypes():
        """Just for better readability, all __misp*type methods return just a list of misp data types

        :returns: misp regkey data types
        :rtype: list
        """
        return ['regkey', 'regkey|value']
    
    @staticmethod
    def __mispfilenametypes():
        """Just for better readability, all __misp*type methods return just a list of misp data types

        :returns: data types containing filenames
        :rtype: list
        """
        return ['filename', 'filename|md5', 'filename|sha1', 'filename|sha256', 'filename|ssdeep', 'filename|sha224',
                'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|tlsh',
                'filename|authentihash']

    def __clean_relatedevent(self, related_events):
        """
        Strip relatedevent sub content of event for lighter output.
        
        :param related_events: 
        :return: 
        """

        response = []
        for event in related_events:
            ev = {}
            ev['info'] = event['Event']['info']
            ev['id'] = event['Event']['id']
            response.append(ev)

        return response


    def __clean_event(self, misp_event):
        """
        Strip event data for lighter output. Analyer report only contains useful data.
        
        :param event: misp event
        :return: misp event
        """

        filters = ['Attribute',
                   'ShadowAttribute',
                   'Org',
                   'ShadowAttribute',
                   'SharingGroup',
                   'sharing_group_id',
                   'disable_correlation',
                   'locked',
                   'publish_timestamp',
                   'attribute_count',
                   'attribute_count',
                   'analysis',
                   'published',
                   'distribution',
                   'proposal_email_lock']

        for filter in filters:
            if filter in misp_event:
                del misp_event[filter]

        if 'RelatedEvent' in misp_event:
            misp_event['RelatedEvent'] = self.__clean_relatedevent(misp_event['RelatedEvent'])


        return misp_event

    def __clean(self, misp_response):
        """
        
        :param misp_response: 
        :return: 
        """
        response = []

        for event in misp_response.get('response', []):
            response.append(self.__clean_event(event['Event']))

        return response

    def __search(self, value, type_attribute):
        """Search method call wrapper.

        :param value: value to search for.
        :type value: str
        :param type_attribute: attribute types to search for.
        :type type_attribute: [list, none]
        """
        results = []
        if not value:
            raise EmptySearchtermError
        for idx, connection in enumerate(self.misp_connections):
            misp_response = connection.search(type_attribute=type_attribute, values=value)
            results.append({'url': connection.root_url,
                            'name': self.misp_name[idx],
                            'result': self.__clean(misp_response)})
        return results

    def search_url(self, searchterm):
        """Search for URLs
        
        :type searchterm: str
        :rtype: list
        """
        return self.__search(type_attribute=self.__mispurltypes(), value=searchterm)

    def search_hash(self, searchterm):
        """Search for hashes
        
        :type searchterm: str
        :rtype: list
        """
        return self.__search(type_attribute=self.__misphashtypes(), value=searchterm)

    def search_domain(self, searchterm):
        """Search for domains
        
        :type searchterm: str
        :rtype: list
        """
        return self.__search(type_attribute=self.__mispdomaintypes(), value=searchterm)

    def search_mail(self, searchterm):
        """Search for emails
        
        :type searchterm: str
        :rtype: list
        """
        return self.__search(type_attribute=self.__mispmailtypes(), value=searchterm)

    def search_ip(self, searchterm):
        """Search for ips
        
        :type searchterm: str
        :rtype: list
        """
        return self.__search(type_attribute=self.__mispiptypes(), value=searchterm)

    def search_registry(self, searchterm):
        """Search for registry keys and values
        
        :type searchterm: str
        :rtype: list
        """
        return self.__search(type_attribute=self.__mispregistrytypes(), value=searchterm)
    
    def search_filename(self, searchterm):
        """Search for filenames
        
        :type searchterm: str
        :rtype: list
        """
        return self.__search(type_attribute=self.__mispfilenametypes(), value=searchterm)

    def searchall(self, searchterm):
        """Search through all attribute types, this could be really slow.
        
        :type searchterm: str
        :rtype: list
        """
        return self.__search(type_attribute=None, value=searchterm)
