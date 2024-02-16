#!/usr/bin/env python3
# encoding: utf-8
import os
import geoip2.database
from geoip2.errors import AddressNotFoundError
from cortexutils.analyzer import Analyzer


class MaxMindAnalyzer(Analyzer):

    def dump_city(self, city):
        return {
            'confidence': city.confidence,
            'geoname_id': city.geoname_id,
            'name': city.name,
            'names': city.names
        }

    def dump_continent(self, continent):
        return {
            'code': continent.code,
            'geoname_id': continent.geoname_id,
            'name': continent.name,
            'names': continent.names,
        }

    def dump_country(self, country):
        return {
            'confidence': country.confidence,
            'geoname_id': country.geoname_id,
            'iso_code': country.iso_code,
            'name': country.name,
            'names': country.names
        }

    def dump_location(self, location):
        return {
            'accuracy_radius': location.accuracy_radius,
            'latitude': location.latitude,
            'longitude': location.longitude,
            'metro_code': location.metro_code,
            'time_zone': location.time_zone
        }

    def dump_traits(self, traits):
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
        taxonomies = []
        level = "info"
        namespace = "MaxMind"
        predicate = "Location"

        if "continent" in raw:
            value = "{}/{}".format(raw["country"]["name"], raw["continent"]["name"])
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)

        if self.data_type == 'ip':
            try:
                data = self.get_data()

                city = geoip2.database.Reader(os.path.dirname(__file__) + '/GeoLite2-City.mmdb').city(data)

                self.report({
                    'city': self.dump_city(city.city),
                    'continent': self.dump_continent(city.continent),
                    'country': self.dump_country(city.country),
                    'location': self.dump_location(city.location),
                    'registered_country': self.dump_country(city.registered_country),
                    'represented_country': self.dump_country(city.represented_country),
                    'subdivisions': self.dump_country(city.subdivisions.most_specific),
                    'traits': self.dump_traits(city.traits)
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
