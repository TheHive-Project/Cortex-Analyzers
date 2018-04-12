from requests_html import HTMLSession
import urllib


class URLhaus:
    def __init__(self, query):
        self.URL = "https://urlhaus.abuse.ch/browse.php"
        self.query = query

    def search(self):
        res = self.fetch()
        return self.parse(res)

    def fetch(self):
        session = HTMLSession()
        return session.get(self.target_url())

    def parse(self, res):
        results = []
        table = res.html.find("table.table", first=True)
        rows = table.find("tr")[1:]
        for row in rows:
            cols = row.find("td")
            results.append({
                "dateadded": cols[0].text,
                "malware_url": cols[1].text,
                "link": cols[1].find("a", first=True).attrs.get("href"),
                "status": cols[2].text,
                "tags": cols[3].text.split(),
                "gsb": cols[4].text,
                "reporter": cols[5].text
            })
        return results

    def target_url(self):
        return "{}?{}".format(
            self.URL,
            urllib.parse.urlencode({"search": self.query})
        )
