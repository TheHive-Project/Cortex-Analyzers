import requests
from datetime import datetime, timedelta
from dateutil.parser import parse
import pytz
from diskcache import Cache


class TorProjectClient:
    """Simple client to query torproject.org for exit nodes.

    The client will download https://check.torproject.org/exit-addresses
    and check if a specified IP address is present in it. If that IP address
    is found it will check for its last update time and return a description
    of the node if its last update time is less than `ttl` seconds ago.

    :param ttl: Tor node will be kept only if its last update was
                less than `ttl` seconds ago. Ignored if `ttl` is 0
    :param cache_duration: Duration before refreshing the cache (in seconds).
                           Ignored if `cache_duration` is 0.
    :param cache_root: Path where to store the cached file
                       downloaded from torproject.org
    :param proxies: Proxies to be using during requests session
    :type ttl: int
    :type cache_duration: int
    :type cache_root: str
    """

    def __init__(
        self,
        ttl=86400,
        cache_duration=3600,
        cache_root="/tmp/cortex/tor_project",
        proxies=None,
    ):
        self.session = requests.Session()
        if proxies:
            self.session.proxies.update(proxies)
        self.delta = None
        self.cache = None
        if ttl > 0:
            self.delta = timedelta(seconds=ttl)
        if cache_duration > 0:
            self.cache = Cache(cache_root)
            self.cache_duration = cache_duration
        self.url = "https://check.torproject.org/exit-addresses"

    __cache_key = __name__ + ":raw_data"

    def _get_raw_data(self):
        try:
            return self.cache["raw_data"]
        except (AttributeError, TypeError):
            return self.session.get(self.url).text
        except KeyError:
            self.cache.set(
                "raw_data",
                self.session.get(self.url).text,
                expire=self.cache_duration,
            )
            return self.cache["raw_data"]

    def search_tor_node(self, ip):
        """Lookup an IP address to check if it is a known tor exit node.

        :param ip: The IP address to lookup
        :type ip: str
        :return: Data relative to the tor node. If `ip`is a tor exit node
                 it will contain a `node` key with the hash of the node and
                 a `last_status` key with the last update time of the node.
                 If `ip` is not a tor exit node, the function will return an
                 empty dictionary.
        :rtype: dict
        """
        data = {}
        tmp = {}
        present = datetime.utcnow().replace(tzinfo=pytz.utc)
        for line in self._get_raw_data().splitlines():
            params = line.split(" ")
            if params[0] == "ExitNode":
                tmp["node"] = params[1]
            elif params[0] == "ExitAddress":
                tmp["last_status"] = params[2] + "T" + params[3] + "+0000"
                last_status = parse(tmp["last_status"])
                if self.delta is None or (present - last_status) < self.delta:
                    data[params[1]] = tmp
                tmp = {}
            else:
                pass
        return data.get(ip, {})
