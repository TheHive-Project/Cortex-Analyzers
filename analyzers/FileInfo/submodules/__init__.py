# from .submodule_metadata import MetadataSubmodule
# from .submodule_gzip import GZIPSubmodule
# from .submodule_pe import PESubmodule

from .submodule_metadata import *
from .submodule_gzip import *
from .submodule_pe import *
from .submodule_pdfid import *


AVAILABLE_SUBMODULES = [MetadataSubmodule(),
           GZIPSubmodule(),
           PESubmodule(),
           PDFIDSubmodule()]