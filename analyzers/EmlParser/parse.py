#!/usr/bin/env python3
# encoding: utf-8
import base64
import binascii
import datetime
import os
import re
from io import BytesIO

import eml_parser
import imgkit
import magic
from PIL import Image
from bs4 import BeautifulSoup
from cortexutils.analyzer import Analyzer


# TODO: Optional: add a flavor: with image (the other one gives all http links found in the message, can be run as a second analysis. Manage PAP/TLP, use at your own risk)


IP_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
EMAIL_REGEX = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)


def extract_ips_from_text(text):
    """Extract valid IPv4 addresses from a text string."""
    return IP_REGEX.findall(text or "")


def extract_emails_from_text(text):
    """Extract email addresses from a text string."""
    return EMAIL_REGEX.findall(text or "")


class EmlParserAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        # filename of the observable
        self.filename = self.getParam("attachment.name", "noname.ext")
        self.filepath = self.getParam("file", None, "File is missing")

        # Gather ConfigurationItems
        self.wkhtmltoimage = {
            "enable": self.get_param("config.email_visualisation", False),
            "path": self.get_param(
                "config.wkhtmltoimage_path", "/usr/bin/wkhtmltoimage"
            ),
            "width_size": self.get_param("config.width_size", 1024),
        }
        self.sanitized_rendering = self.get_param("config.sanitized_rendering", False)

    def run(self):
        if self.data_type == "file":
            try:
                parsing_result = parseEml(
                    self.filepath,
                    self.job_directory,
                    self.wkhtmltoimage,
                    self.sanitized_rendering,
                )
                self.report(parsing_result)
            except Exception as e:
                self.unexpectedError(e)

        else:
            self.notSupported()

    def summary(self, raw):
        # Initialise
        taxonomies = []
        level = "info"
        namespace = "EmlParser"
        predicate_attachments = "Attachments"
        predicate_urls = "Urls"
        value_attachments = "0"
        value_urls = "0"

        # Get values
        if "attachments" in raw:
            value_attachments = len(raw["attachments"])
        if "iocs" in raw and "url" in raw.get("iocs", {}):
            value_urls = len(raw["iocs"]["url"])

        # Build summary
        taxonomies.append(
            self.build_taxonomy(
                level, namespace, predicate_attachments, value_attachments
            )
        )
        taxonomies.append(
            self.build_taxonomy(level, namespace, predicate_urls, value_urls)
        )
        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        if not self.auto_extract:
            return []

        artifacts = []
        seen = set()
        urls = raw.get("iocs").get("url")
        ip = raw.get("iocs").get("ip")
        domains = raw.get("iocs").get("domain")
        mail_addresses = raw.get("iocs").get("email")
        hashes = raw.get("iocs").get("hash")

        if urls:
            for u in urls:
                key = ("url", str(u["data"]))
                if key not in seen:
                    seen.add(key)
                    artifacts.append(
                        self.build_artifact(
                            "url", str(u["data"]), tags=u["tag"] + ["autoImport:true"]
                        )
                    )
        if ip:
            for i in ip:
                key = ("ip", str(i["data"]))
                if key not in seen:
                    seen.add(key)
                    artifacts.append(
                        self.build_artifact(
                            "ip", str(i["data"]), tags=i["tag"] + ["autoImport:true"]
                        )
                    )
        if mail_addresses:
            for e in mail_addresses:
                key = ("mail", str(e["data"]))
                if key not in seen:
                    seen.add(key)
                    artifacts.append(
                        self.build_artifact(
                            "mail", str(e["data"]), tags=e["tag"] + ["autoImport:true"]
                        )
                    )
        if domains:
            for d in domains:
                key = ("domain", str(d["data"]))
                if key not in seen:
                    seen.add(key)
                    artifacts.append(
                        self.build_artifact("domain", str(d["data"]), tags=d["tag"])
                    )
        if hashes:
            for h in hashes:
                hash_key = ("hash", str(h["hash"]))
                if hash_key not in seen:
                    seen.add(hash_key)
                    artifacts.append(
                        self.build_artifact(
                            "hash",
                            str(h["hash"]),
                            tags=["body:attachment", "autoImport:true"] + h["tag"],
                        )
                    )
                fname_key = ("filename", str(h["filename"]))
                if fname_key not in seen:
                    seen.add(fname_key)
                    artifacts.append(
                        self.build_artifact(
                            "filename",
                            str(h["filename"]),
                            tags=["body:attachment", "autoImport:true"] + h["tag"],
                        )
                    )
                filepath = os.path.join(self.job_directory, "output", h.get("filename"))
                file_key = ("file", filepath)
                if file_key not in seen:
                    seen.add(file_key)
                    artifacts.append(
                        self.build_artifact(
                            "file",
                            filepath,
                            tags=["body:attachment", "autoImport:true"] + h["tag"],
                        )
                    )
        return artifacts


def _add_ioc(ioc_list, data, tags):
    """Add IOC to list, merging tags if the same data value already exists."""
    for existing in ioc_list:
        if existing["data"] == data:
            for tag in tags:
                if tag not in existing["tag"]:
                    existing["tag"].append(tag)
            return
    ioc_list.append({"data": data, "tag": list(tags)})


def parseEml(filepath, job_directory, wkhtmltoimage, sanitized_rendering):
    ep = eml_parser.EmlParser(include_raw_body=True, include_attachment_data=True)
    with open(filepath, "rb") as f:
        raw_email = f.read()

    decoded_email = ep.decode_email_bytes(raw_email)

    ##
    ## Results
    ##
    result = dict()
    iocs = dict()
    iocs["ip"] = list()
    iocs["domain"] = list()
    iocs["url"] = list()
    iocs["email"] = list()
    iocs["hash"] = list()
    iocs["files"] = list()

    ##
    ## Extract raw email
    ##
    result["raw_email"] = raw_email.decode("utf-8", errors="replace")
    ##
    ## Extract SMTP envelope
    ##
    headers = dict()
    headers["return-path"] = (
        decoded_email.get("header").get("header").get("return-path", "")
    )
    headers["delivered-to"] = (
        decoded_email.get("header").get("header").get("delivered-to", "")
    )
    headers["x-delivered-to"] = (
        decoded_email.get("header").get("header").get("x-delivered-to", "")
    )

    ##
    ## Extract Headers
    ##
    headers["from"] = decoded_email.get("header").get("header").get("from", [])
    headers["to"] = decoded_email.get("header").get("header").get("to", [])
    headers["cc"] = decoded_email.get("header").get("header").get("cc", [])
    headers["bcc"] = decoded_email.get("header").get("header").get("bcc", [])
    headers["reply-to"] = decoded_email.get("header").get("header").get("reply-to", [])
    headers["subject"] = decoded_email.get("header").get("header").get("subject", "")
    headers["date"] = decoded_email.get("header").get("header").get("date", [""])[0]
    headers["received"] = decoded_email.get("header").get("received")
    # Make dates ready for json
    for h in headers["received"]:
        if isinstance(h.get("date"), datetime.datetime):
            d = h.get("date").isoformat()
            h["date"] = d
    result["headers"] = headers

    ##
    ## Extract body text/plain and text/html
    ##
    body = dict()
    if "body" in decoded_email:
        body["text_plain"] = list()
        body["text_html"] = list()
        for b in decoded_email.get("body"):
            ## text/plain
            if b.get("content_type") == "text/plain":
                body["text_plain"].append(b)
                b["beautified_text"] = BeautifulSoup(
                    b.get("content"), "html.parser"
                ).prettify()
                for url in ep.get_uri_ondata(b.get("content")):
                    _add_ioc(iocs["url"], url, ["body:text/plain", "content-ioc"])
                for ip in extract_ips_from_text(b.get("content")):
                    _add_ioc(iocs["ip"], ip, ["body:text/plain", "content-ioc"])
                for email in extract_emails_from_text(b.get("content")):
                    _add_ioc(iocs["email"], email, ["body:text/plain", "content-ioc"])

            ## text/html
            elif b.get("content_type") == "text/html":
                for url in ep.get_uri_ondata(b.get("content")):
                    _add_ioc(iocs["url"], url, ["body:text/html", "content-ioc"])
                # Extract IPs and emails from visible text (strip HTML tags)
                visible_text = BeautifulSoup(
                    b.get("content"), "html.parser"
                ).get_text()
                for ip in extract_ips_from_text(visible_text):
                    _add_ioc(iocs["ip"], ip, ["body:text/html", "content-ioc"])
                for email in extract_emails_from_text(visible_text):
                    _add_ioc(iocs["email"], email, ["body:text/html", "content-ioc"])

                ## Generate rendering image if option is enabled
                if wkhtmltoimage.get("enable"):
                    try:
                        img_file = convert_png(
                            b.get("content"), 0, wkhtmltoimage.get("path"), "/tmp"
                        )
                    except Exception as e:
                        try:
                            b["content"] = remove_html_imports(b["content"], e)
                            img_file = convert_png(
                                b.get("content"), 0, wkhtmltoimage.get("path"), "/tmp"
                            )
                        except Exception as e:
                            b[
                                "content"
                            ] = '<html><body><div style="background-color:red; color:white; text-align: center;"><strong>WARNING:</strong> this page cannot be rendered because some imports failed</div></body></html>'
                            img_file = convert_png(
                                b.get("content"), 0, wkhtmltoimage.get("path"), "/tmp"
                            )
                    b["rendered_html"] = "data:{};base64,{}".format(
                        "image/png",
                        base64_image(
                            img_file.get("img_path"), wkhtmltoimage.get("width_size")
                        ),
                    )
                    b["beautified_html"] = BeautifulSoup(
                        b.get("content"), "html.parser"
                    ).prettify()

                body["text_html"].append(b)
    result["body"] = body

    ##
    ## Extract Attachments
    ##
    result["attachments"] = list()
    if "attachment" in decoded_email.keys():
        for a in decoded_email.get("attachment"):
            a["mime"] = magic.from_buffer(binascii.a2b_base64(a.get("raw")))
            if isinstance(a.get("raw"), bytes):
                path, filename = os.path.split(a.get("filename", ""))
                if path != "":
                    os.umask(0)
                    os.makedirs(
                        f"{job_directory}/output/{path}", exist_ok=True, mode=0o777
                    )
                filepath = os.path.join(job_directory, "output", path, filename)
                with open(filepath, "wb") as f:
                    f.write(base64.b64decode(a["raw"]))
                f.close()
                a["raw"] = a.get("raw").decode("ascii")
            result["attachments"].append(a)
            iocs["hash"].append(
                {
                    "hash": a.get("hash").get("sha256"),
                    "filename": a.get("filename"),
                    "tag": [
                        "content-type:{}".format(
                            a.get("content_header").get("content-type")[0].split(";")[0]
                        )
                    ],
                }
            )

    ##
    ## Extract IOCs
    ##
    for ip in decoded_email.get("header").get("received_ip", []):
        _add_ioc(iocs["ip"], ip, ["header:Received", "mail-relay"])
    for domain in decoded_email.get("header").get("received_domain", []):
        _add_ioc(iocs["domain"], domain, ["header:Received", "mail-relay"])
    ### Email
    for field in [
        "cc",
        "bcc",
        "delivered_to",
        "received_foremail",
    ]:
        for email in decoded_email.get("header").get(field, []):
            if field == "delivered_to":
                _add_ioc(iocs["email"], email, ["header:To", "envelope"])
            else:
                _add_ioc(iocs["email"], email, ["header:{}".format(field.capitalize()), "envelope"])
    from_addr = decoded_email.get("header").get("from", "")
    if from_addr:
        _add_ioc(iocs["email"], from_addr, ["header:From", "envelope"])
        if "@" in from_addr:
            from_domain = from_addr.split("@")[-1].strip().rstrip(">").lower()
            if from_domain:
                _add_ioc(iocs["domain"], from_domain, ["header:From", "sender-domain"])
    ### Reply-To
    for reply_to in decoded_email.get("header").get("header").get("reply-to", []):
        for addr in extract_emails_from_text(reply_to):
            _add_ioc(iocs["email"], addr, ["header:Reply-To", "envelope"])
            if "@" in addr:
                rt_domain = addr.split("@")[-1].strip().lower()
                if rt_domain:
                    _add_ioc(iocs["domain"], rt_domain, ["header:Reply-To", "reply-to-domain"])

    result["iocs"] = iocs

    return result


def convert_png(content: str, i, wkhtmltoimage_path: str, output_path: str):
    config = imgkit.config(wkhtmltoimage=wkhtmltoimage_path)
    options = {
        "no-images": "",
        "encoding": "UTF-8",
        "disable-javascript": "",
        "load-media-error-handling": "ignore",
        "load-error-handling": "ignore",
    }
    imgkit.from_string(
        content, "{}/{}.png".format(output_path, i), options=options, config=config
    )
    return {"index": i, "img_path": "{}/{}.png".format(output_path, i)}


def base64_image(img_path, width):
    """
    :param content: raw image
    :type content: raw
    :param width: size of the return image
    :type width: int
    :return: base64 encoded image
    :rtype: string
    """
    try:
        image = Image.open(img_path)
        ft = image.format
        wpercent = width / float(image.size[0])
        if image.size[0] > width:
            hsize = int(float(image.size[1]) * float(wpercent))
            image = image.resize((width, hsize), Image.ANTIALIAS)
        ImgByteArr = BytesIO()
        image.save(ImgByteArr, format=ft)
        ImgByteArr = ImgByteArr.getvalue()
        with BytesIO(ImgByteArr) as bytes:
            encoded = base64.b64encode(bytes.read())
            base64_image = encoded.decode()
        return base64_image

    except Exception as e:
        return "No image"


def remove_html_imports(html_str, txt):
    """
    Remove all import statements from the html string.
    """
    body_pattern = r"<body[^>]*>"
    import_pattern = '\S+="https?:\/\/\S+"'
    warning = '<div style="background-color:red; color:white; text-align: center;"><strong>WARNING:</strong> this page was modified for rendering because some imports failed</div>'
    splitted_html = html_str.splitlines()
    for index, line in enumerate(splitted_html):
        if re.search(body_pattern, line):
            splitted_html.insert(index + 1, warning)
        sanitazed_line = re.sub(import_pattern, "", line)
        splitted_html[index] = sanitazed_line
    return "\r\n".join(splitted_html)


if __name__ == "__main__":
    EmlParserAnalyzer().run()
