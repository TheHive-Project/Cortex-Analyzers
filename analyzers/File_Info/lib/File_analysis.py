#!/usr/bin/env python
# encoding: utf-8

import sys
import os
import json
import pefile
import hashlib
import pydeep
import magic
import pyexifinfo
import re
import pehashng
from lib.pdfid import *
from StringIO import StringIO

reload(sys)
sys.setdefaultencoding('utf-8')

class file:

    def __init__(self, filepath):
        self.path = filepath
        self.filename = os.path.basename(filepath)
        self.stream = open(filepath, 'r').read()
        if magic.Magic(mime=True).from_file(filepath) == 'application/x-dosexec':
            try:
                self.pe = pefile.PE(filepath)
                self.pedict = self.pe.dump_dict()
            except Exception as excp:
                print('Failed processing %s') % filepath




    # Magic
    def magic(self):
        return magic.Magic().from_file(self.path)

    def mimetype(self):
        return magic.Magic(mime=True).from_file(self.path)

    # FileType
    def filetype(self):
        return pyexifinfo.fileType(self.path)

    # ExifTool
    def exif(self):
        exifreport=pyexifinfo.get_json(self.path)
        # result = json.dumps(exifreport).decode('unicode-escape').encode('utf8')
        result=dict((key,value) for key,value in exifreport[0].iteritems() if not (key.startswith("File") or key.startswith("SourceFile")))

        return result

    # File hash
    def md5(self):
        return hashlib.md5(self.stream).hexdigest();

    def sha1(self):
        return hashlib.sha1(self.stream).hexdigest();

    def sha256(self):
        return hashlib.sha256(self.stream).hexdigest();

    def ssdeep(self):
        return pydeep.hash_file(self.path)

    # PE: impash #
    def imphash(self):
        return self.pe.get_imphash()

    # PE: pehash #
    def pehash(self):
        if self.pe:
            return  pehashng.pehashng(self.pe)

    # Fileinfo #
    def filesize(self):
        return os.path.getsize(self.path)

    ##########
    # PE     #
    ##########

    # PE : info #
    def PE_info(self):
        table=[]
        try:
            for fileinfo in self.pe.FileInfo:
                if fileinfo.Key == 'StringFileInfo':
                    for stringtable in fileinfo.StringTable:
                        for entry in stringtable.entries.items():
                            table.append({'Info':entry[0], 'Value':entry[1]})
            return table
        except Exception as excp:
            return 'None'

    # PE: type #
    def PEtype(self):

        if self.pe and self.pe.is_dll():
            return "DLL"
        if self.pe and self.pe.is_driver():
            return "DRIVER"
        if self.pe and self.pe.is_exe():
            return "EXE"

    # PE:  Timestamp #
    def PE_CompilationTimestamp(self):
        if self.pe:
            return self.pedict['FILE_HEADER']['TimeDateStamp']['Value']

    # PE: OS Version #
    def PE_OperatingSystem(self):
        if self.pe:
            return str(self.pedict['OPTIONAL_HEADER']['MajorOperatingSystemVersion']['Value']) + "." \
               + str(self.pedict['OPTIONAL_HEADER']['MinorOperatingSystemVersion']['Value'])

    # PE:Machine type #
    def PE_Machine(self):
        if self.pe:
            machinetype = self.pedict['FILE_HEADER']['Machine']['Value']
            mt = {'0x14c': 'x86', '0x0200': 'Itanium', '0x8664': 'x64'}
            if type(machinetype) is int:
                return mt[str(hex(machinetype))]
            else:
                return str(machinetype) + ' => Not x86/64 or Itanium'

    # PE:Entry Point #
    def PE_EntryPoint(self):
        if self.pe:
            return hex(self.pedict['OPTIONAL_HEADER']['AddressOfEntryPoint']['Value'])

    # PE:IAT list of {'entryname':'name', 'symbols':[list of symbols]}#
    def PE_iat(self):
        if self.pe:
            table = []
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                imp = {'entryname': '', 'symbols': []}
                imp['entryname']=entry.dll
                for symbol in entry.imports:
                    imp['symbols'].append(symbol.name)
                table.append(imp)
            return table

    # PE Resources : WORK IN PROGRESS #
    def PE_resources(self):
        for rsrc in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for entry in rsrc.directory.entries:
                print entry.name.__str__()
                for i in entry.directory.entries:
                    print i.data.lang
                    print i.data.sublang

    # PE:Sections list of {Name, Size, Entropy, MD5, SHA1, SHA256, SHA512} #
    def PE_sections(self):
        if self.pe:
            table = []
            for entry in self.pe.sections:
                sect = {'entryname':str(entry.Name),'SizeOfRawData':hex(entry.SizeOfRawData),
                        'Entropy':entry.get_entropy(),
                        'MD5':entry.get_hash_md5(),
                        'SHA1':entry.get_hash_sha1(),
                        'SHA256':entry.get_hash_sha256(),
                        'SHA512':entry.get_hash_sha512()}
                table.append(sect)
                sect = {}
            return table


    # PE :Return dump_dict() for debug only #
    def dump(self):
        if self.pe:
            return self.pedict




    #########
    # PDF   #
    #########

    # PDFiD #
    def pdfid_cmd(self):
        try:
            oParser = optparse.OptionParser(usage='usage: %prog [options] [pdf-file|zip-file|url|@file] ...\n')
            oParser.add_option('-s', '--scan', action='store_true', default=False, help='scan the given directory')
            oParser.add_option('-a', '--all', action='store_true', default=False, help='display all the names')
            oParser.add_option('-e', '--extra', action='store_true', default=False, help='display extra data, like dates')
            oParser.add_option('-f', '--force', action='store_true', default=False, help='force the scan of the file, even without proper %PDF header')
            oParser.add_option('-d', '--disarm', action='store_true', default=False, help='disable JavaScript and auto launch')
            oParser.add_option('-p', '--plugins', type=str, default='', help='plugins to load (separate plugins with a comma , ; @file supported)')
            oParser.add_option('-c', '--csv', action='store_true', default=False, help='output csv data when using plugins')
            oParser.add_option('-m', '--minimumscore', type=float, default=0.0, help='minimum score for plugin results output')
            oParser.add_option('-v', '--verbose', action='store_true', default=False, help='verbose (will also raise catched exceptions)')
            oParser.add_option('-S', '--select', type=str, default='', help='selection expression')
            oParser.add_option('-o', '--output', type=str, default='', help='output to log file')
            (options, args) = oParser.parse_args()

            return json.loads(PDFiD2JSON(PDFiD(self.path, options.all, options.extra, options.disarm, options.force), options.force))
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            self.unexpectedError(e)

    #############
    # MS OFFICE #
    #############

    # Olevba #
    # using https://bitbucket.org/decalage/oletools/wiki/olevba
    def olevba_info(self):

        try:
            __import__('imp').find_module('oletools')
            from oletools.olevba import VBA_Parser, VBA_Scanner
            from oletools.olevba import __version__ as olevbaVersion
        except ImportError:
            self.error('Import Error: Module oletools not found')
        # Redirect stderr to devnull in case input file is not a valid office document. When parsing a non valid
        # document VBA Parser raises an error to stderr.
        redir_err = sys.stderr = StringIO()
        try:
            vba = VBA_Parser(self.path)
            result = {
                'Suspicious': False,
                'Base64 Strings': False,
                'Hex Strings': False,
                'Version': olevbaVersion
            }
        except TypeError:
            self.error('File type error: ' + redir_err.getvalue())

        # set stderr back to original __stderr__
        sys.stderr = sys.__stderr__

        if vba.detect_vba_macros():
            result['vba'] = 'VBA Macros found'
            streams = []
            for (filename, stream_path, vba_filename, vba_code) in vba.extract_macros():
                vba_scanner = VBA_Scanner(vba_code)
                scan_results = vba_scanner.scan(include_decoded_strings=False)
                vba_scan_results = []
                for kw_type, keyword, description in scan_results:
                    vba_scan_results.append({
                        'type': str(kw_type).encode('utf-8'),
                        'keyword': str(keyword).encode('utf-8'),
                        'description': str(description).encode('utf-8')
                    })

                    if (kw_type == 'Suspicious'):
                        result['Suspicious'] = True
                    if (keyword == 'Base64 Strings'):
                        result['Base64 Strings'] = True
                    if (keyword == 'Hex Strings'):
                        result['Hex Strings'] = True

                streams.append({
                    'Filename': self.filename,
                    'OLE stream': stream_path,
                    'VBA filename': vba_filename.decode('unicode-escape').encode('utf-8'),
                    'VBA code': vba_code.decode('unicode-escape').encode('utf-8'),
                    'scan_result': vba_scan_results
                })
            result['streams'] = streams
        else:
            result['vba'] = 'No VBA Macros found'

        return result
