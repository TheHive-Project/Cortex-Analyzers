#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
from outlook_msg import Message
import iocextract
import extract_msg
import tempfile
import hashlib

class MsgParserAnalyzer(Analyzer):
 
    def __init__(self):
        Analyzer.__init__(self)
        self.filepath = self.get_param('file', None, 'File is missing')        

    def summary(self, raw):
        taxonomies = []

        if 'attachments' in raw:
            taxonomies.append(self.build_taxonomy('info', 'MsgParser', 'Attachments', len(raw['attachments'])))

        return { 'taxonomies': taxonomies }

    # @brief Bringing up observables from the mail to TheHive
    def artifacts(self, raw):
        artifacts = []
        urls = list(set(iocextract.extract_urls(str(raw))))
        ipv4s = list(set(iocextract.extract_ipv4s(str(raw))))
        mail_addresses = list(set(iocextract.extract_emails(str(raw))))
        hashes = list(set(iocextract.extract_hashes(str(raw))))
        
        # Extract each attachment to send as an observable
        for attachment in self.attachments_paths:
            artifacts.append(self.build_artifact('file', attachment, tlp=3))

        for u in urls:
            artifacts.append(self.build_artifact('url', str(u)))
    
        for i in ipv4s:
            artifacts.append(self.build_artifact('ip', str(i)))
    
        for e in mail_addresses:
            artifacts.append(self.build_artifact('mail', str(e)))
        
        for h in hashes:
            artifacts.append(self.build_artifact('hash', str(h)))

        # Cleanup the temporary folder
        self.temp_dir.cleanup()

        return artifacts
    
  
    # @brief Returns the hash of the input file
    # @param data_bytes: content of the file readed
    # @param mode: Hash algorithms mode
    def get_hash(self, data_bytes, mode='md5'):
        h = hashlib.new(mode)
        h.update(data_bytes)
        digest = h.hexdigest()
        return digest

    # @brief Main function to retrieve mail information and attachments
    def parseMsg(self):

        # Extract all information from the mail with extract_msg
        msg = extract_msg.Message(self.filepath)

        result = dict()
        result['subject'] = str(msg.subject)
        result['date'] = str(msg.date)
        result['receivers'] = str(msg.to)
        result['sender'] = str(msg.sender)
        result['bcc'] = str(msg.bcc)
        result['headers'] = str(msg.header)
        result['body'] = str(msg.body)
        result['MessageID'] = str(msg.messageId)
        result['XoriginatingIP'] = str(msg.header.get('x-originating-ip'))
        
        result['attachments'] = list()

        # Retrieves the list of attachments and saves them in a temporary folder. 
        # Then for each attachment, calculates the different Hash of the attachment
        self.attachments_paths = []
        self.temp_dir = tempfile.TemporaryDirectory()

        with open(self.filepath) as msg_file:
            msg = Message(msg_file)
        
        for an_attachment in msg.attachments:
            attachment_name = '{}/{}'.format(str(self.temp_dir.name), str(an_attachment.filename)) 
            self.attachments_paths.append(attachment_name)
            
            with an_attachment.open() as attachment_fp, open(attachment_name, 'wb') as output_fp:
                data = attachment_fp.read()
                output_fp.write(data)    
                attachment_sum_up = dict()
                attachment_sum_up['filename'] =  attachment_name.split('/')[-1]
                # Calculates the hash of each attachment
                attachment_sum_up['md5'] = self.get_hash(data, 'md5')
                attachment_sum_up['sha1'] = self.get_hash(data, 'sha1')
                attachment_sum_up['sha256'] = self.get_hash(data, 'sha256')
                result['attachments'].append(attachment_sum_up)

        return result

    def run(self):
        if self.data_type == 'file':       
            parsingResult = self.parseMsg()
            self.report(parsingResult)
        else:
            self.notSupported()
        
if __name__ == '__main__':
    MsgParserAnalyzer().run()
