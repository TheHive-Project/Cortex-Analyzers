#!/usr/bin/env python
# encoding: utf-8
import sys
import os
import json
import geoip2.database
from geoip2.errors import AddressNotFoundError
from cortexutils.analyzer import Analyzer


class MaxMindAnalyzer(Analyzer):

    def dumpCity(self, city):
        return {
            'confidence': city.confidence,
            'geoname_id': city.geoname_id,
            'name': city.name,
            'names': city.names
        }

    def dumpContinent(self, continent):
        return {
            'code': continent.code,
            'geoname_id': continent.geoname_id,
            'name': continent.name,
            'names': continent.names,
        }

    def dumpCountry(self, country):
        return {
            'confidence': country.confidence,
            'geoname_id': country.geoname_id,
            'iso_code': country.iso_code,
            'name': country.name,
            'names': country.names
        }

    def dumpLocation(self, location):
        return {
            'accuracy_radius': location.accuracy_radius,
            'latitude': location.latitude,
            'longitude': location.longitude,
            'metro_code': location.metro_code,
            'time_zone': location.time_zone
        }

    def dumpTraits(self, traits):
        return {
            'autonomous_system_number': traits.autonomous_system_number,
            'autonomous_system_organization': traits.autonomous_system_organization,
            'domain': traits.domain,
            'ip_address': traits.ip_address,
            'is_anonymous_proxy': traits.is_anonymous_proxy,
            'is_satellite_provider': traits.is_satellite_provider,
            'isp': traits.isp,
            'organization': traits.organization,
            'user_type': traits.user_type
        }

    def summary(self, raw):
        result = {}

        if("continent" in raw):
            result["country"] = raw["country"]["name"]
            result["continent"] = raw["continent"]["name"]

        return result

    def run(self):
        Analyzer.run(self)

        if self.data_type == 'ip':
            try:
                data = self.getData()

                city = geoip2.database.Reader(os.path.dirname(__file__) + '/GeoLite2-City.mmdb').city(data)
                country = geoip2.database.Reader(os.path.dirname(__file__) + '/GeoLite2-Country.mmdb').country(data)

                self.report({
                    'city': self.dumpCity(city.city),
                    'continent': self.dumpContinent(city.continent),
                    'country': self.dumpCountry(city.country),
                    'location': self.dumpLocation(city.location),
                    'registered_country': self.dumpCountry(city.registered_country),
                    'represented_country': self.dumpCountry(city.represented_country),
                    'subdivisions': self.dumpCountry(city.subdivisions.most_specific),
                    'traits': self.dumpTraits(city.traits)
                })
            except ValueError as e:
                self.error('Invalid IP address')
            except AddressNotFoundError as e:
                self.error('Unknown IP address')
            except Exception as e:
                self.unexpectedError(type(e))
        else:
            self.notSupported()


if __name__ == '__main__':
    MaxMindAnalyzer().run()
