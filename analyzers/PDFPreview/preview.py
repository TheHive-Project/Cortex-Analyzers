#!/usr/bin/env python3
import base64
import re
import magic
from io import BytesIO

from cortexutils.analyzer import Analyzer
from pdf2image import convert_from_path, pdfinfo_from_path

MAX_RENDER_DIMENSION = 4000          # pixels, longest side of a rendered page


def _render_pages(filepath, dpi, max_pages):
    """Render pages via poppler. Returns (images, total_page_count, error)."""
    images, page_count, error = [], None, None
    kwargs = {}
    # pdfinfo is best-effort: it can fail on a PDF that pdftoppm still renders.
    try:
        info = pdfinfo_from_path(filepath)
        page_count = info.get("Pages")
        # Clamp output size so a huge MediaBox cannot produce a giant image.
        m = re.match(r"([\d.]+)\s*x\s*([\d.]+)", str(info.get("Page size", "")))
        if m and max(float(m.group(1)), float(m.group(2))) * dpi / 72 > MAX_RENDER_DIMENSION:
            kwargs["size"] = MAX_RENDER_DIMENSION
    except Exception:
        pass

    try:
        images = convert_from_path(filepath, dpi=dpi, last_page=max_pages, **kwargs)
    except Exception as e:
        error = str(e)[:500] or e.__class__.__name__
    return images, page_count, error


class PDFPreviewAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.filepath = self.get_param("file", None, "File parameter is missing.")
        self.filename = self.get_param("filename", "unknown.pdf")
        self.max_pages = self.get_param("config.max_pages", 10)
        self.dpi = self.get_param("config.dpi", 100)

    def run(self):
        if self.data_type != "file":
            self.notSupported()
            return

        try:
            mime = magic.Magic(mime=True).from_file(self.filepath)
            # The PDF spec allows junk before the %PDF- header, so such files can be detected as text/plain while poppler still renders them.
            if mime != "application/pdf":
                with open(self.filepath, "rb") as f:
                    if b"%PDF-" not in f.read(1024):
                        self.error("File is not a PDF (detected MIME: {})".format(mime))
                        return

            result = {"filename": self.filename, "mime": mime}

            images, page_count, render_error = _render_pages(self.filepath, self.dpi, self.max_pages)
            result["page_count_total"] = page_count
            result["render_error"] = render_error
            result["pages_rendered"] = len(images)
            result["pages"] = []
            for i, img in enumerate(images):
                buf = BytesIO()
                img.convert("RGB").save(buf, format="JPEG", quality=85)
                b64 = base64.b64encode(buf.getvalue()).decode()
                result["pages"].append({
                    "index": i + 1,
                    "image": "data:image/jpeg;base64,{}".format(b64),
                })

            self.report(result)
        except Exception as e:
            self.unexpectedError(e)

    def summary(self, raw):
        taxonomies = []
        namespace = "PDFPreview"

        if raw.get("render_error") and not raw.get("pages_rendered"):
            # Password-protected attachments are a common evasion trick
            taxonomies.append(self.build_taxonomy("suspicious", namespace, "Render", "failed"))
        else:
            taxonomies.append(self.build_taxonomy("info", namespace, "Pages", raw.get("pages_rendered", 0)))

        return {"taxonomies": taxonomies}


if __name__ == "__main__":
    PDFPreviewAnalyzer().run()
