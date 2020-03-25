#!/usr/bin/env python3
# encoding: utf-8
import email.parser
import eml_parser
from cortexutils.analyzer import Analyzer
import magic
import binascii
import hashlib
import base64
from pprint import pprint

#Observables imports
from cortexutils.extractor import Extractor
from builtins import str as unicode
import re

class CustomExtractor(Extractor):
    def __init__(self, ignore=None):
        #Extractor.__init__(self)
        self.ignore = ignore
        self.regex = self.__init_regex()
    
    @staticmethod
    def __init_regex():
        
        logging.info("Preparing regex statements")
        
        """
        Returns compiled regex list.

        :return: List of {type, regex} dicts
        :rtype: list
        """

        #### Generic regexes
        
        # IPv4
        regex = [{
            'types': ['ip'],
            'regex': re.compile(r'(?:^|\D)((?:25[0-5]|2[0-4]\d|[1]\d\d|[1-9]\d|[0-9])\.(?:25[0-5]|2[0-4]\d|[1]\d\d|[1-9]\d|[0-9])\.(?:25[0-5]|2[0-4]\d|[1]\d\d|[1-9]\d|[0-9])\.(?:25[0-5]|2[0-4]\d|[1]\d\d|[1-9]\d|[0-9]))(?:\D|$)', re.MULTILINE)
        }]

        # URL
        regex.append({
            'types': ['url','fqdn','domain','uri_path'],
            'regex': re.compile(r'((?:http|https):\/\/((?:(?:.*?)\.)?(.*?(?:\.\w+)+))\/?([a-zA-Z0-9\/\-\_\.\~\=\?]+\??)?)', re.MULTILINE)
        })

        # mail
        regex.append({
            'types': ['mail','domain'],
            'regex': re.compile(r'((?:[a-zA-Z0-9\/\-\_\.\+]+)@{1}([a-zA-Z0-9\-\_]+\.[a-zA-Z0-9\-\_\.]+)+)', re.MULTILINE)
        })
        
        ### Mail Specific regexes

        return regex
    
    def __findmatch(self, value):
        """Checks if the given value is contains regexes

        :param value: The value to check
        :type value: str or number
        :return: Data type of value, if known, else empty string
        :rtype: str
        """
        found_observables = []
        if isinstance(value, (str, unicode)):
            for r in self.regex:
                #content = value
                #logging.info("Checking regex: {}".format(r.get('regex')))
                #logging.info("Checking value: {}".format(value))
                matches = re.findall(r.get('regex'), value)
                #logging.info("Matches: {}".format(str(matches)))
                if len(matches) > 0:
                    
                    for found_observable in matches:
                        if isinstance(found_observable, tuple):
                            i = 0
                            for groups in found_observable:
                                found_observables.append({
                                    'type': r.get('types')[i],
                                    'value': found_observable[i]
                                    })
                                i += 1
                        else:
                            found_observables.append({
                                'type': r.get('types')[0],
                                'value': found_observable
                                })
            if len(found_observables) > 0:
                return found_observables
            else:
                return ''

        # if self.ignore:
            # if isinstance(value, str) and self.ignore in value:
                # return ''
            # if self.ignore == value:
                # return ''
        # return ''
        
    def check_iterable(self, iterable):
        """
        Checks values of a list or a dict on ioc's. Returns a list of dict {type, value}. Raises TypeError, if iterable
        is not an expected type.

        :param iterable: List or dict of values
        :type iterable: list dict str
        :return: List of ioc's matching the regex
        :rtype: list
        """
        results = []
        # Only the string left
        logging.info("Checking content of variable")
        if isinstance(iterable, (str, unicode)):
            #logging.info("Content is a string")
            dt = self.__findmatch(iterable)
            logging.info("dt = {}".format(str(dt)))
            if len(dt) > 0:
                results.extend(dt)
        elif isinstance(iterable, list):
            #logging.info("Content is a list")
            for item in iterable:
                if isinstance(item, list) or isinstance(item, dict):
                    results.extend(self.check_iterable(item))
                else:
                    dt = self.__findmatch(item)
                    #logging.info("dt = {}".format(str(dt)))
                    if len(dt) > 0:
                        results.extend(dt)
        elif isinstance(iterable, dict):
            #logging.info("Content is a dict")
            for _, item in iterable.items():
                if isinstance(item, list) or isinstance(item, dict):
                    results.extend(self.check_iterable(item))
                else:
                    dt = self.__findmatch(item)
                    logging.info("dt = {}".format(str(dt)))
                    if len(dt) > 0:
                        results.extend(dt)
        else:
            raise TypeError('Not supported type.')

        logging.info('results: {}'.format(str(results)))
        results_dedup = self.deduplicate(results)
        return results_dedup
        
    def deduplicate(self, list_of_objects):
        dedup_list = []
        for object in list_of_objects:
            present = False
            for new_object in dedup_list:
                if object['type'] == new_object['type'] and object['value'] == new_object['value']:
                    present = True
            if not present:
                dedup_list.append(object)
        return dedup_list


class EmlParserAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

        #filename of the observable
        self.filename = self.getParam('attachment.name', 'noname.ext')

        #filepath to the observable, looks like /tmp/cortex-4224850437865873235-datafile
        self.filepath = self.getParam('file', None, 'File is missing')

    def run(self):
        if self.data_type == 'file':
            try:
                parsingResult = parseEml(self.filepath)
                self.report(parsingResult)
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "EmlParser"
        predicate = "Attachments"
        value = "\"0\""
        
        if "attachments" in raw:
            value = len(raw["attachments"])
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}
        
    def artifacts(self, raw):
        # Use the regex extractor, if auto_extract setting is not False
        logging.info("Looking for artifacts")
        if self.auto_extract:
            logging.info("Looking for artifacts2")
            extractor = CustomExtractor(ignore=self.get_data())
            return extractor.check_iterable(raw)

        # Return empty list
        return []
    


def parseEml(filepath):

    result = dict()
    result['subject'] = str()
    result['date'] = str()
    result['receivers'] = str()
    result['displayFrom'] = str()
    result['sender'] = str()
    result['topic'] = str()
    result['bcc'] = str()
    result['displayto'] = str()
    result['headers'] = str()
    result['body'] = str()
    result['attachments'] = list()

    #read the file
    with open(filepath, 'r') as f:
        raw_eml = f.read()

    #parsing the headers with the email library
    #cause eml_parser does not provide raw headers (as far as I know)
    hParser = email.parser.HeaderParser()
    h = hParser.parsestr(raw_eml)
    result['headers'] = dict(h)

    parsed_eml = eml_parser.eml_parser.decode_email(filepath, include_raw_body=True, include_attachment_data=True)
    #parsed_eml['header'].keys() gives:
    #dict_keys(['received_foremail', 'from', 'date', 'received_domain', 'to', 'header', 'received_ip', 'subject', 'received'])

    result['subject'] = ', '.join(parsed_eml.get('header', '').get('header', '').get('subject', ''))
    result['date'] = ', '.join(parsed_eml.get('header', '').get('header', '').get('date', ''))
    result['receivers'] = ', '.join(parsed_eml.get('header', '').get('to', ''))
    result['displayFrom'] = parsed_eml.get('header', '').get('from', '')
    result['sender'] = ', '.join(parsed_eml.get('header', '').get('header', '').get('x-env-sender', ''))
    result['topic'] = ', '.join(parsed_eml.get('header', '').get('header', '').get('thread-topic', ''))
    result['bcc'] = parsed_eml.get('header', '').get('header', '').get('bcc', '')
    result['displayto'] = ', '.join(parsed_eml.get('header', '').get('header', '').get('to', ''))

    #for some emails, the body field is empty because the email body is
    #identified as an attachment
    if parsed_eml['body']:
        #normal case
        result['body'] = parsed_eml['body'][0]['content']
    else:
        #email body is in attachment
        #from what I've seen, there are 2 attachments
        #one with the email body as text
        #and one with the email body as text but wrapped in html
        #let's arbitrary take the one wrapped in html as body
        for attachment in parsed_eml['attachment']:
            if 'HTML text' in attachment['content_header']['content-description']:
                result['body'] = base64.b64decode(attachment['raw']).decode('utf-8')

    #attachments
    try:
        for attachment in parsed_eml['attachment']:
            attachmentSumUp = dict()
            attachmentSumUp['filename'] = attachment.get('filename', '')

            #because of module conflict name with magic
            #eml-parser does not provide the mime type
            #it has to be calculated, the attachment is in base64
            attachmentSumUp['mime'] = magic.from_buffer(binascii.a2b_base64(attachment['raw']))
            attachmentSumUp['extension'] = attachment.get('extension', '')
            attachmentSumUp['md5'] = attachment['hash']['md5']
            attachmentSumUp['sha1'] = attachment['hash']['sha1']
            attachmentSumUp['sha256'] = attachment['hash']['sha256']
            result['attachments'].append(attachmentSumUp)

    except KeyError as e:
        pass

    return result

if __name__ == '__main__':
    EmlParserAnalyzer().run()
