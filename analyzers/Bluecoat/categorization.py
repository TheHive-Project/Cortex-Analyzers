#!/usr/bin/env python3
import json
import re
import requests

from cortexutils.analyzer import Analyzer


class BluecoatAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.BC_url = 'https://sitereview.bluecoat.com/'
        self.BC_parameter_name = 'url'
        self.BC_sitereview = 'sitereview.jsp'
        self.BC_rest_page = 'rest/categorization'

    def parse_answer(self, categorization, ratedate):
        """
        Extract desired fields using RegEx
        """
        regex_category_id = r'catdesc\.jsp\?catnum=(\d+)'
        regex_category = r'(?<=>)[A-Za-z\/\- ]+'
        regex_date = r'Last Time Rated\/Reviewed:(.*)<img'

        if categorization != "":
            result = {}
            try:
                result['category'] = re.findall(regex_category, categorization)[0]
                result['id'] = re.findall(regex_category_id, categorization)[0]
                result['date'] = re.findall(regex_date, ratedate)
                if not result['date']:
                    result['date'] = False
                else:
                    result['date'] = result['date'][0]

            except KeyError:
                result = None

            return result
        else:
            return None

    def call_bluecoat_api(self, host):
        """
        Return JSON formatted data provided by Bluecoat REST API
        """
        session = requests.session()
        try:
            # First connexion in order to get a SESSION ID, used for the second request
            session.get(self.BC_url + self.BC_sitereview)
            BC_json_answer = session.post(self.BC_url + self.BC_rest_page, data={self.BC_parameter_name: host})
            return json.loads(BC_json_answer.text)
        except Exception as e:
            self.error(e)

    def url_to_domain(self, url):
        """
        Retrieve domain from url
        """
        regex_domain = r'(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n]+)\/?'
        try:
            return re.findall(regex_domain, url)[0]
        except:
            return None

    def summary(self, raw):
        taxonomies = []
        level = 'info'
        namespace = 'BlueCoat'
        predicate = 'Category'
        value = '{}'.format(raw['category'])

        if value == '\"Uncategorized\"':
            level = 'suspicious'

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {'taxonomies': taxonomies}

    def run(self):
        json_answer = None
        if self.data_type == 'domain' or self.data_type == 'url' or self.data_type == 'fqdn':
            if self.data_type == 'url':
                domain = self.url_to_domain(self.get_data())
                if domain:
                    json_answer = self.call_bluecoat_api(domain)
                else:
                    self.error('Domain not found')

            else:
                json_answer = self.call_bluecoat_api(self.get_data())

            if json_answer:
                try:
                    result = self.parse_answer(json_answer['categorization'], json_answer['ratedate'])
                    result['host'] = self.get_data()
                    return self.report(result)
                except Exception:
                    try:
                        return self.error('{} : {}'.format(json_answer['errorType'], json_answer['error']))
                    except Exception:
                        return self.error('Undefinded Bluecoat error.')
        else:
            return self.error('Invalid data type !')


if __name__ == '__main__':
    BluecoatAnalyzer().run()
