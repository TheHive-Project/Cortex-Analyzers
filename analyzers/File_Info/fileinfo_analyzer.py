#!/usr/bin/env python
# encoding: utf-8


import sys
import json
import codecs
import magic
from lib.File_analysis import file
from cortexutils.analyzer import Analyzer


class FileAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        self.filename = self.get_param('filename', 'noname.ext')
        self.filepath = self.get_param('file', None, 'File is missing')

    def file_info(self, report):
        result = report
        f = file(self.filepath)
        try:
            result['Mimetype'] = f.mimetype()
        except Exception as excp:
            self.error(str(excp))
        result['Exif'] = f.exif()
        result['Magic'] = f.magic()
        result['filetype'] = f.filetype()
        result['Identification'] = {'MD5': f.md5(),
                                    'SHA1': f.sha1(),
                                    'SHA256': f.sha256(),
                                    'ssdeep': f.ssdeep()}
        return result

    # PE_Info analyzer
    def pe_info(self, report):
        result = report
        f = file(self.filepath)
        result['Identification'].update({'impash': f.imphash(),
                                         'ssdeep': f.ssdeep(),
                                         'pehash': f.pehash(),
                                         'OperatingSystem': f.PE_OperatingSystem(),
                                         'Type': f.PEtype()})
        result['PE'] = {}
        result['PE']['BasicInformation'] = {'FileInfo': f.PE_info(),
                                            'FileSize': f.filesize(),
                                            'TargetMachine': f.PE_Machine(),
                                            'CompilationTimestamp': f.PE_CompilationTimestamp(),
                                            'EntryPoint': f.PE_EntryPoint()}

        result['PE']['Sections'] = f.PE_sections()
        result['PE']['ImportAdressTable'] = f.PE_iat()
        return result

    def pe_summary(self, report):
        result = {}
        detections = {}
        result.update({'detections': detections})
        result.update({'filetype': report['filetype']})
        return result

    # PDFiD results analysis -- input for full report and summary
    def pdfid_analysis(self, report):
        # Parse detections
        detections = {}
        filetype = report['filetype']
        keywords = report['PDF']['pdfid'][0]['pdfid']['keywords']['keyword']
        score = 0
        for obj in keywords:
            if obj['name'] in ['/JavaScript', '/OpenAction', '/RichMedia', '/ObjStm', '/Launch']:
                score = score + obj['count']
                detections[obj['name']] = obj['count']

        if score > 0:
            suspicious = True
        else:
            suspicious = False
        return {'score': score, 'detections': detections, 'suspicious': suspicious, 'filetype': filetype}

    # PDF_Info analyzer
    def pdf_info(self, report):
        result = report
        f = file(self.filepath)
        result['PDF'] = {}
        result['PDF']['pdfid'] = f.pdfid_cmd()
        result['PDF']['pdfid'][0]['pdfid']['filename'] = self.filename
        result['PDF']['pdfid'][0]['detections'] = self.pdfid_analysis(result)['detections']
        result['PDF']['pdfid'][0]['score'] = self.pdfid_analysis(result)['score']
        result['PDF']['pdfid'][0]['suspicious'] = self.pdfid_analysis(result)['suspicious']
        return result

    def pdf_summary(self, report):
        result = {}
        result.update({'score': self.pdfid_analysis(report)['score']})
        result.update({'suspicious': self.pdfid_analysis(report)['suspicious']})
        result.update({'detections': self.pdfid_analysis(report)['detections']})
        result.update({'filetype': self.pdfid_analysis(report)['filetype']})
        return result

    # Office_Info
    def msoffice_info(self, report):
        result = report
        f = file(self.filepath)
        result['MSOffice'] = {}
        result['MSOffice']['olevba'] = f.olevba_info()

        return result

    # MSOffice_Summary
    def msoffice_summary(self, report):
        r = report['MSOffice']['olevba']
        result = {}
        detections = {}
        result.update({'filetype': report['filetype']})
        detections['vba'] = r['vba']
        detections['Base64 Strings'] = r['Base64 Strings']
        detections['Hex Strings'] = r['Hex Strings']
        result.update({'detections': detections})
        result.update({'suspicious': r['Suspicious']})
        return result

    # SUMMARY
    def summary(self, full_report):
        taxonomies = []
        level = "info"
        namespace = "FileInfo"
        predicate = "Filetype"

        if full_report['Mimetype'] in ['application/x-dosexec']:
            pereport = self.pe_summary(full_report)
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, pereport['filetype']))
        elif full_report['Mimetype'] in ['application/pdf']:
            pdfreport = self.pdf_summary(full_report)
            value = "\"{}\"".format(pdfreport['filetype'])
            if pdfreport['suspicious']:
                level = 'suspicious'
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        elif (full_report['filetype'] in ['DOC', 'DOCM', 'DOCX',
                                          'XLS', 'XLSM', 'XLSX',
                                          'PPT', "PPTM", 'PPTX']):
            msreport = self.msoffice_summary(full_report)
            value = "\"{}\"".format(msreport['filetype'])
            if msreport['suspicious']:
                level = 'suspicious'
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        else:
            value = "\"{}\"".format(full_report['filetype'])
            level = 'info'
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        result = {'taxonomies': taxonomies}
        return result

    def specific_info(self, report):
        # run specific program for PE
        if report['Mimetype'] in ['application/x-dosexec']:
            self.pe_info(report)
        # run specific program for PDF
        if report['Mimetype'] in ['application/pdf']:
            self.pdf_info(report)
        # run specific program for MSOffice
        if (report['filetype'] in ['DOC', 'DOCM', 'DOCX',
                                   'XLS', 'XLSM', 'XLSX',
                                   'PPT', "PPTM", 'PPTX']):
            self.msoffice_info(report)

    def run(self):
        full_report = {}
        if self.data_type == 'file':
            try:
                self.file_info(full_report)
                self.specific_info(full_report)
                self.report(full_report)
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == '__main__':
    FileAnalyzer().run()
