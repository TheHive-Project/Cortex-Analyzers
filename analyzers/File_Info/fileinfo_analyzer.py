#!/usr/bin/env python
# encoding: utf-8


import sys
import json
import codecs
import magic
from  lib.File_analysis import file
from cortexutils.analyzer import Analyzer


class FileAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        self.filename = self.getParam('attachment.name', 'noname.ext')
        self.filepath = self.getParam('file', None, 'File is missing')


    def FileInfo(self, report):
        result = report
        f = file(self.filepath)
        try:
            result['Mimetype'] = f.mimetype()
        except Exception as excp:
            error(str(excp))
        result['Exif'] = f.exif()
        result['Magic']= f.magic()
        result['filetype']=f.filetype()
        result['Identification']= {'MD5': f.md5(),
                                'SHA1':f.sha1(),
                                'SHA256':f.sha256(),
                                'ssdeep':f.ssdeep()}
        return result

    # PE_Info analyzer
    def PE_Info(self, report):
        result = report
        f = file(self.filepath)
        result['Identification'].update({'impash':f.imphash(),
                                'ssdeep':f.ssdeep(),
                                'pehash':f.pehash(),
                                'OperatingSystem':f.PE_OperatingSystem(),
                                'Type':f.PEtype()})
        result['PE']={}
        result['PE']['BasicInformation'] = {'FileInfo':f.PE_info(),
                                  'FileSize': f.filesize(),
                                  'TargetMachine' : f.PE_Machine(),
                                  'CompilationTimestamp' : f.PE_CompilationTimestamp(),
                                  'EntryPoint':f.PE_EntryPoint()}

        result['PE']['Sections'] = f.PE_sections()
        result['PE']['ImportAdressTable'] = f.PE_iat()
        return result


    def PE_Summary(self, report):
        result = {}
        detections = {}
        result.update({'detections': detections})
        result.update({'filetype': report['filetype']})
        return result

    # PDFiD results analysis -- input for full report and summary
    def Pdfid_analysis(self, report):
        # Parse detections
        detections = {}
        filetype = report['filetype']
        keywords = report['PDF']['pdfid'][0]['pdfid']['keywords']['keyword']
        for obj in keywords:
            if obj['name'].startswith('/'):
                detections[obj['name']] = obj['count']
        # Count detections
        countJavaScript = detections['/JavaScript']
        countOpenAction = detections['/OpenAction']
        countRichMedia = detections['/RichMedia']
        countObjStm = detections['/ObjStm']
        countOpenAction = detections['/OpenAction']
        countLaunch = detections['/Launch']
        detect = detections
        detections = {}
        detections['/JavaScript'] = detect['/JavaScript']
        detections['/OpenAction'] = detect['/OpenAction']
        detections['/RichMedia'] = detect['/RichMedia']
        detections['/ObjStm'] = detect['/ObjStm']
        detections['/OpenAction'] = detect['/OpenAction']
        detections['/Launch'] = detect['/Launch']
        score = countJavaScript + countOpenAction + countRichMedia + countObjStm + countOpenAction + countLaunch
        if score > 0:
            suspicious = True
        else:
            suspicious = False
        return {'score':score, 'detections':detections, 'suspicious': suspicious, 'filetype': filetype}

    # PDF_Info analyzer
    def PDF_Info(self, report):
        result = report
        f = file(self.filepath)
        result['PDF']={}
        result['PDF']['pdfid'] =f.pdfid_cmd()
        result['PDF']['pdfid'][0]['pdfid']['filename'] = self.filename
        result['PDF']['pdfid'][0]['detections'] = self.Pdfid_analysis(result)['detections']
        result['PDF']['pdfid'][0]['score'] = self.Pdfid_analysis(result)['score']
        result['PDF']['pdfid'][0]['suspicious'] = self.Pdfid_analysis(result)['suspicious']
        return result

    def PDF_Summary(self,report):
        result = {}
        detections = {}
        result.update({'score': self.Pdfid_analysis(report)['score']})
        result.update({'suspicious': self.Pdfid_analysis(report)['suspicious']})
        result.update({'detections': self.Pdfid_analysis(report)['detections']})
        result.update({'filetype': self.Pdfid_analysis(report)['filetype']})
        return result

    # Office_Info
    def MSOffice_Info(self,report):
        result=report
        f = file(self.filepath)
        result['MSOffice'] = {}
        result['MSOffice']['olevba'] = f.olevba_info()

        return result

    # MSOffice_Summary
    def MSOffice_Summary(self,report):
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
    def summary(self, fullReport):

        taxonomy = {"level": "info", "namespace": "FileInfo", "predicate": "Filetype", "value": 0}
        taxonomies = []

        if fullReport['Mimetype'] in ['application/x-dosexec']:
            pereport = self.PE_Summary(fullReport)
            taxonomy["value"] = pereport['filetype']
            taxonomies.append(taxonomy)
        elif fullReport['Mimetype'] in ['application/pdf']:
            pdfreport = self.PDF_Summary(fullReport)
            taxonomy['value'] = pdfreport['filetype']
            if pdfreport['suspicious']:
                taxonomy['level'] = 'warning'
            taxonomies.append(taxonomy)
        elif (fullReport['filetype'] in ['DOC','DOCM','DOCX',
                                    'XLS', 'XLSM', 'XLSX',
                                    'PPT', "PPTM", 'PPTX']):
            msreport = self.MSOffice_Summary(fullReport)
            taxonomy['value'] = msreport['filetype']
            if msreport['suspicious']:
                taxonomy['level'] = 'warning'
            taxonomies.append(taxonomy)
        else:
            taxonomy['value'] = fullReport['filetype']
            taxonomies.append(taxonomy)

        result = {'taxonomies': taxonomies}
        return result





    def SpecificInfo(self,report):
        # run specific program for PE
        if report['Mimetype'] in ['application/x-dosexec']:
            self.PE_Info(report)
        # run specific program for PDF
        if report['Mimetype'] in ['application/pdf']:
            self.PDF_Info(report)
        # run specific program for MSOffice
        if (report['filetype'] in ['DOC','DOCM','DOCX',
                                    'XLS', 'XLSM', 'XLSX',
                                    'PPT', "PPTM", 'PPTX']):
            self.MSOffice_Info(report)


    def run(self):
        fullReport = {}
        if self.data_type == 'file':
            try:
                self.FileInfo(fullReport)
                self.SpecificInfo(fullReport)
                self.report(fullReport)
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == '__main__':
    FileAnalyzer().run()
