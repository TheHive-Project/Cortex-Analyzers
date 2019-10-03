from .submodule_oletools import OLEToolsSubmodule
from .submodule_pe import PESubmodule
from .submodule_pdfid import PDFIDSubmodule
from .submodule_outlook import OutlookSubmodule
from .submodule_rtfobj import RTFObjectSubmodule
from .submodule_ioc_parser import IOCPSubmodule

available_submodules = [
    PESubmodule(),
    OLEToolsSubmodule(),
    PDFIDSubmodule(),
    IOCPSubmodule(),
    OutlookSubmodule(),
    RTFObjectSubmodule()
]
