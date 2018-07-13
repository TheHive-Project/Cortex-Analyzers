from bs4 import BeautifulSoup
from diskcache import Cache
import requests


class URLhaus:
    """Simple client to query URLhaus by abuse.ch.
    :param query: domain, url or hash.
    :param cache_duration: Duration before refreshing the cache (in seconds).
                           Ignored if `cache_duration` is 0.
    :param cache_root: Path where to store the cached file.
    :type query: string
    :type cache_duration: int
    :type cache_root: str
    """

    def __init__(self,
                 query,
                 cache_duration=300,
                 cache_root="/tmp/cortex/URLhaus"):
        self.URL = "https://urlhaus.abuse.ch/browse.php"
        self.query = query
        self.cache = None
        if cache_duration > 0:
            self.cache = Cache(cache_root)
            self.cache_duration = cache_duration

    def _get_raw_data(self):
        try:
            return self.cache[self.query.encode('utf-8')]
        except(AttributeError, TypeError):
            return self.fetch()
        except KeyError:
            self.cache.set(
                self.query.encode('utf-8'),
                self.fetch(),
                expire=self.cache_duration)
            return self.cache[self.query.encode('utf-8')]

    def search(self):
        res = self._get_raw_data()
        return self.parse(res)

    def fetch(self):
        payload = {"search": self.query}
        return requests.get(self.URL, params=payload).text

    def parse(self, doc):
        results = []
        soup = BeautifulSoup(doc, "html.parser")
        table = soup.find("table", class_="table")
        rows = table.find_all("tr")[1:]
        for row in rows:
            cols = row.find_all("td")
            results.append({
                "dateadded": cols[0].text,
                "malware_url": cols[1].text,
                "link": cols[1].find("a").attrs.get("href"),
                "status": cols[2].text,
                "tags": cols[3].text.split(),
                "gsb": cols[4].text,
                "reporter": cols[5].text
            })
        return results
