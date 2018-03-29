from .submodule_oletools import OLEToolsSubmodule
from .submodule_pe import PESubmodule
from .submodule_pdfid import PDFIDSubmodule

available_submodules = [
    PESubmodule(),
    OLEToolsSubmodule(),
    PDFIDSubmodule()
]
