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


def parseEml(filepath):

    result = dict()
    result['subject'] = str()
    result['date'] = str()
    result['receivers'] = str()
    result['displayFrom'] = str()
    result['sender'] = str()
    result['topic'] = str()
    result['bcc'] = str()
    result['displayTo'] = str()
    result['headers'] = str()
    result['body'] = str()
    result['attachments'] = list()

    #read the file
    with open(filepath, 'r') as f:
        raw_eml = f.read()

    #parsing the headers with the email library
    #cause eml_parser does not provide raw headers (as far as I know)
    #splited string because it was returning the body inside 'Content-Type'
    hParser = email.parser.HeaderParser()
    h = str(hParser.parsestr(raw_eml))
    result['headers'] = h[:h.index('Content-Type:')]

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
    result['displayTo'] = ', '.join(parsed_eml.get('header', '').get('header', '').get('to', ''))

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
            if 'content-description' in attachment['content_header'] and 'HTML text' in attachment['content_header']['content-description']:
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
