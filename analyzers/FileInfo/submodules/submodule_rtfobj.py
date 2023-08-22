import io
import os.path

from .submodule_base import SubmoduleBaseclass
from oletools.rtfobj import RtfObjParser, RtfObject, re_executable_extensions, olefile
from oletools import oleobj


class RTFObjectSubmodule(SubmoduleBaseclass):
    """Inspect RTF files using rtfobj which is part of oletools"""

    def __init__(self):
        SubmoduleBaseclass.__init__(self)
        self.name = "rtfobj"

    def check_file(self, **kwargs):
        if kwargs.get("mimetype") == "text/rtf":
            return True
        return False

    def module_summary(self):
        """Count the malicious and suspicious sections, check for CVE description"""
        suspicious = 0
        malicious = 0
        count = 0
        cve = False
        taxonomies = []

        for section in self.results:
            if section["submodule_section_content"]["class"] == "malicious":
                malicious += 1
            elif section["submodule_section_content"]["class"] == "suspicious":
                suspicious += 1

            if "CVE" in section["submodule_section_content"]["clsid_description"]:
                cve = True
            count += 1

        if malicious > 0:
            taxonomies.append(
                self.build_taxonomy(
                    "malicious", "FileInfo", "MaliciousRTFObjects", malicious
                )
            )

        if suspicious > 0:
            taxonomies.append(
                self.build_taxonomy(
                    "suspicious", "FileInfo", "SuspiciousRTFObjects", suspicious
                )
            )

        if cve:
            taxonomies.append(
                self.build_taxonomy(
                    "malicious", "FileInfo", "PossibleCVEExploit", "True"
                )
            )

        taxonomies.append(self.build_taxonomy("info", "FileInfo", "RTFObjects", count))

        self.summary["taxonomies"] = taxonomies
        return self.summary

    def analyze_objects(self, path):
        data = None
        with io.open(path, "rb") as fh:
            data = fh.read()

        parser = RtfObjParser(data)
        parser.parse()
        for idx, rtfobj in enumerate(parser.objects):
            if rtfobj.is_ole:
                if rtfobj.format_id == oleobj.OleObject.TYPE_EMBEDDED:
                    obj_type = "{} (Embedded)".format(rtfobj.format_id)
                elif rtfobj.format_id == oleobj.OleObject.TYPE_LINKED:
                    obj_type = "{} (Linked)".format(rtfobj.format_id)
                else:
                    obj_type = "{} (Unknown)".format(rtfobj.format_id)

                if rtfobj.is_package:
                    obj_html_class = "suspicious"
                    _, ext = os.path.splitext(rtfobj.filename)
                    if re_executable_extensions.match(ext):
                        obj_html_class = "malicious"
                else:
                    obj_html_class = "info"

                try:
                    if rtfobj.clsid:
                        obj_clsid = rtfobj.clsid
                        if rtfobj.clsid_desc:
                            obj_clsid_desc = rtfobj.clsid_desc
                            if "CVE" in obj_clsid_desc:
                                obj_html_class = "malicious"
                    else:
                        obj_clsid = "Not available"
                        obj_clsid_desc = "No CLSID related description available."
                except AttributeError:
                    obj_clsid = "Not available"
                    obj_clsid_desc = "No CLSID related description available."

                if "equation" in str(rtfobj.class_name).lower():
                    obj_clsid_desc += " (The class name suggests an Equation Editor referencing OLE object.)"
                    obj_html_class = "malicious"

                self.add_result_subsection(
                    "OLE object #{}".format(idx),
                    {
                        "address": "{}".format(hex(rtfobj.start)),
                        "class": obj_html_class,
                        "type": obj_type,
                        "filename": rtfobj.filename
                        if rtfobj.filename
                        else "Not available",
                        "classname": str(rtfobj.class_name)
                        if rtfobj.class_name
                        else "Not available",
                        "size": rtfobj.oledata_size,
                        "clsid": obj_clsid,
                        "clsid_description": obj_clsid_desc,
                        "source_path": rtfobj.src_path
                        if rtfobj.src_path
                        else "Not available",
                        "temp_path": rtfobj.temp_path
                        if rtfobj.temp_path
                        else "Not available",
                    },
                )
            else:
                self.add_result_subsection(
                    "(Non) OLE object #{}".format(idx),
                    {
                        "index": "0x{}".format(rtfobj.start),
                        "class": "info",
                        "type": "Not a valid OLE object",
                    },
                )

    def analyze_file(self, path):
        self.analyze_objects(path)
        return self.results, None