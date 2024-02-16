#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
##################################### TERMS OF USE ###########################################
# The following code is provided for demonstration purpose only, and should not be used      #
# without independent verification. Recorded Future makes no representations or warranties,  #
# express, implied, statutory, or otherwise, regarding any aspect of this code or of the     #
# information it may retrieve, and provides it both strictly “as-is” and without assuming    #
# responsibility for any information it may retrieve. Recorded Future shall not be liable    #
# for, and you assume all risk of using, the foregoing. By using this code, Customer         #
# represents that it is solely responsible for having all necessary licenses, permissions,   #
# rights, and/or consents to connect to third party APIs, and that it is solely responsible  #
# for having all necessary licenses, permissions, rights, and/or consents to any data        #
# accessed from any third party API.                                                         #
##############################################################################################
"""

import json
import urllib.error
import urllib.request
from urllib.parse import urlencode, quote_plus

from cortexutils.analyzer import Analyzer

APP_VERSION = "2.0"
APP_ID = "ps-thehive-analyzer/{}".format(APP_VERSION)
IP_DATA_TYPE = "ip"
DOMAIN_DATA_TYPE = "domain"
FQDN_DATA_TYPE = "fqdn"
HASH_DATA_TYPE = "hash"
RF_API = "https://api.recordedfuture.com/v2/"
URL_DATA_TYPE = "url"
DEFAULT_LINKS_MAP = {
    'Links_Threat_Actors': ["No Threat Actor Links Found"],
    'Links_Tools_Malware': ["No Malware Links Found"],
    'Links_TTPs_Mitre': ["No MITRE ATT&CK TTP Links Found"],
    'Links_TTPs_Attack_Vector': ["No Attack Vector Links Found"],
    'Links_Indicators_IP': ["No IP Address Links Found"],
    'Links_Indicators_Domain': ["No Domain Links Found"],
    'Links_Indicators_URL': ["No URL Links Found"],
    'Links_Indicators_Hash': ["No Hash Links Found"],
    'Links_Detection_Malware_Sig': ["No Malware Signature Links Found"],
    'Links_Victims_Org': ["No Victim Organization Links Found"],
    'Links_Victims_IP': ["No Victim IP Address Links Found"],
    'Links_Exploit_Vuln': ["No Vulnerability Links Found"],
}


class RecordedFuture(Analyzer):
    """Recorded Future Analyzer class used for observable enrichment and to format the report."""

    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param("config.key", None, "Recorded Future token is missing")

    def lookup_observable(self, observable, data_type):
        """Query the Recorded Future API for entity enrichment.

        Return Risk, Links, Related Entities, Intelligence Card link, and Counts.

        Args:
            observable (string): Case observable to enrich with Recorded Future
            data_type (string): the observable's data type

        Returns:
            dict: the Recorded Future JSON response from observable lookup
        """
        # if analyzer is ran on a URL observable, encode url string before sending to API
        if data_type == URL_DATA_TYPE:
            observable = quote_plus(observable)
        # if observable is a fqdn in TheHive, use the Recorded Future domain endpoint
        elif data_type == FQDN_DATA_TYPE:
            data_type = DOMAIN_DATA_TYPE

        # URL to query Recorded Future API
        params = {'fields': 'aiInsights,counts,entity,intelCard,links,relatedEntities,risk'}
        url = RF_API + ("%s/%s?%s") % (data_type, observable, urlencode(params))

        token = self.api_key
        headers = {'X-RFToken': token, 'User-Agent': APP_ID}
        req = urllib.request.Request(url, None, headers)

        json_response = {}
        try:
            with urllib.request.urlopen(req) as res:
                json_response = json.loads(res.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            self.error("HTTP Error reason: " + e.reason)
        except IOError as e:
            self.error(str(e))

        return json_response

    def add_related_entities(self, related_entities, entities_list):
        """
        Add related entities to the analyzer report if they contain 5 or more co-occurrences.

        Args:
            related_entities (list): related entities returned from the API query
            entities_list (list): append entities to this list if they pass the check
        """
        for related in related_entities:
            if int(related['count']) > 4:
                entities_list.append(related['entity']['name'])

    def format_related_entities(self, json_response, dict_report):
        """
        Get related entities from the JSON response and format into the report.

        Args:
            json_response (dict): API response containing entity context
            dict_report (dict): analyzer report content

        Returns:
            dict: the analyzer report content with related entities
        """
        # Initializing List variables used to store the wanted information
        malwareCategory = []
        relatedHash = []
        relatedIpAddress = []
        relatedThreatActor = []
        relatedInternetDomainName = []
        relatedMalware = []
        relatedAttackVector = []

        try:
            for relatedEntity in json_response['data']['relatedEntities']:
                if relatedEntity['type'] == "RelatedMalwareCategory":
                    self.add_related_entities(relatedEntity['entities'], malwareCategory)
                if relatedEntity['type'] == "RelatedHash":
                    self.add_related_entities(relatedEntity['entities'], relatedHash)
                if relatedEntity['type'] == "RelatedIpAddress":
                    self.add_related_entities(relatedEntity['entities'], relatedIpAddress)
                if relatedEntity['type'] == "RelatedThreatActor":
                    self.add_related_entities(relatedEntity['entities'], relatedThreatActor)
                if relatedEntity['type'] == "RelatedInternetDomainName":
                    self.add_related_entities(relatedEntity['entities'], relatedInternetDomainName)
                if relatedEntity['type'] == "RelatedMalware":
                    self.add_related_entities(relatedEntity['entities'], relatedMalware)
                if relatedEntity['type'] == "RelatedAttackVector":
                    self.add_related_entities(relatedEntity['entities'], relatedAttackVector)
        except KeyError:
            pass

        if not relatedThreatActor:
            relatedThreatActor.append("No Related Threat Actor Found")
        if not malwareCategory:
            malwareCategory.append("No Malware Category Found")
        if not relatedHash:
            relatedHash.append("No Related Hashes Found")
        if not relatedIpAddress:
            relatedIpAddress.append("No Related IP Addresses Found")
        if not relatedInternetDomainName:
            relatedInternetDomainName.append("No Related Domain Names Found")
        if not relatedMalware:
            relatedMalware.append("No Malware Family Found")
        if not relatedAttackVector:
            relatedAttackVector.append("No Related Attack Vector Found")

        dict_report['Malware_Category'] = malwareCategory
        dict_report['Malware_Family'] = relatedMalware
        dict_report['Threat_Actor'] = relatedThreatActor
        dict_report['Related_Hashes'] = relatedHash
        dict_report['Related_IPs'] = relatedIpAddress
        dict_report['Related_Domains'] = relatedInternetDomainName
        dict_report['Attack_Vector'] = relatedAttackVector

        return dict_report

    def add_link_to_list(self, entities, links):
        """
        Add Linked entity to the provided links list if it is not a duplicate.

        Args:
            entities (list): the list of linked entities to be added
            links (list): append entities to this list if they are unique
        """
        for entity in entities:
            if entity['name'] not in links:
                links.append(entity['name'])

    def add_actors_tools_ttps(self, section_lists, dict_report):
        """
        Parse Actors, Tools & TTPs from links and format into the report.

        Args:
            section_lists (list): entity lists under links Actors, Tools & TTPs sections
            dict_report (dict): analyzer report content

        Returns:
            dict: the analyzer report content with Actors, Tools & TTPs
        """
        linksThreatActors = dict_report.get('Links_Threat_Actors', [])
        linksToolsMalware = dict_report.get('Links_Tools_Malware', [])
        linksTTPsMitre = dict_report.get('Links_TTPs_Mitre', [])
        linksTTPsAttackVector = dict_report.get('Links_TTPs_Attack_Vector', [])

        for section_list in section_lists:
            type_name = section_list.get('type', {}).get('name')

            if type_name == "Threat Actor":
                self.add_link_to_list(section_list['entities'], linksThreatActors)
            elif type_name == "Malware":
                self.add_link_to_list(section_list['entities'], linksToolsMalware)
            elif type_name == "MitreAttackIdentifier":
                self.add_link_to_list(section_list['entities'], linksTTPsMitre)
            elif type_name == "AttackVector":
                self.add_link_to_list(section_list['entities'], linksTTPsAttackVector)

        dict_report['Links_Threat_Actors'] = linksThreatActors
        dict_report['Links_Tools_Malware'] = linksToolsMalware
        dict_report['Links_TTPs_Mitre'] = linksTTPsMitre
        dict_report['Links_TTPs_Attack_Vector'] = linksTTPsAttackVector

        return dict_report

    def add_indicators_detection_rules(self, section_lists, dict_report):
        """
        Parse Indicators & Detection Rules from links and format into the report.

        Args:
            section_lists (list): entity lists under links Indicators & Detection Rules sections
            dict_report (dict): analyzer report content

        Returns:
            dict: the analyzer report content with Indicators & Detection Rules
        """
        linksIndicatorsIP = dict_report.get('Links_Indicators_IP', [])
        linksIndicatorsDomain = dict_report.get('Links_Indicators_Domain', [])
        linksIndicatorsURL = dict_report.get('Links_Indicators_URL', [])
        linksIndicatorsHash = dict_report.get('Links_Indicators_Hash', [])
        linksDetectionMalwareSig = dict_report.get('Links_Detection_Malware_Sig', [])

        for section_list in section_lists:
            type_name = section_list.get('type', {}).get('name')

            if type_name == "IpAddress":
                self.add_link_to_list(section_list['entities'], linksIndicatorsIP)
            elif type_name == "InternetDomainName":
                self.add_link_to_list(section_list['entities'], linksIndicatorsDomain)
            elif type_name == "URL":
                self.add_link_to_list(section_list['entities'], linksIndicatorsURL)
            elif type_name == "Hash":
                self.add_link_to_list(section_list['entities'], linksIndicatorsHash)
            elif type_name == "MalwareSignature":
                self.add_link_to_list(section_list['entities'], linksDetectionMalwareSig)

        dict_report['Links_Indicators_IP'] = linksIndicatorsIP
        dict_report['Links_Indicators_Domain'] = linksIndicatorsDomain
        dict_report['Links_Indicators_URL'] = linksIndicatorsURL
        dict_report['Links_Indicators_Hash'] = linksIndicatorsHash
        dict_report['Links_Detection_Malware_Sig'] = linksDetectionMalwareSig

        return dict_report

    def add_victims_exploit_targets(self, section_lists, dict_report):
        """
        Parse Victims & Exploit Targets from links and format into the report.

        Args:
            section_lists (list): entity lists under links Victims & Exploit Targets sections
            dict_report (dict): analyzer report content

        Returns:
            dict: the analyzer report content with Victims & Exploit Targets
        """
        linksVictimsOrg = dict_report.get('Links_Victims_Org', [])
        linksVictimsIP = dict_report.get('Links_Victims_IP', [])
        linksExploitVuln = dict_report.get('Links_Exploit_Vuln', [])

        for section_list in section_lists:
            type_name = section_list.get('type', {}).get('name')

            if type_name == "Organization":
                self.add_link_to_list(section_list['entities'], linksVictimsOrg)
            elif type_name == "IpAddress":
                self.add_link_to_list(section_list['entities'], linksVictimsIP)
            elif type_name == "CyberVulnerability":
                self.add_link_to_list(section_list['entities'], linksExploitVuln)

        dict_report['Links_Victims_Org'] = linksVictimsOrg
        dict_report['Links_Victims_IP'] = linksVictimsIP
        dict_report['Links_Exploit_Vuln'] = linksExploitVuln

        return dict_report

    def add_default_links_values(self, dict_report):
        """
        Set default text to indicate when no links exist.
        This prevents formatting issues within the analyzer report.

        Args:
            dict_report (dict): analyzer report content

        Returns:
            dict: the analyzer report content with links
        """
        for key in DEFAULT_LINKS_MAP:
            if not dict_report.get(key):
                dict_report[key] = DEFAULT_LINKS_MAP[key]

        return dict_report

    def format_links(self, json_response, dict_report):
        """
        Get links from the JSON response and format into the report.

        Args:
            json_response (dict): API response containing entity context
            dict_report (dict): analyzer report content

        Returns:
            dict: the analyzer report content with links
        """
        try:
            for hit in json_response['data']['links']['hits']:
                for section in hit['sections']:
                    if section['lists']:
                        section_name = section.get('section_id', {}).get('name')

                        if section_name == "Actors, Tools & TTPs":
                            dict_report = self.add_actors_tools_ttps(section['lists'], dict_report)
                        elif section_name == "Indicators & Detection Rules":
                            dict_report = self.add_indicators_detection_rules(
                                section['lists'], dict_report
                            )
                        elif section_name == "Victims & Exploit Targets":
                            dict_report = self.add_victims_exploit_targets(
                                section['lists'], dict_report
                            )
        except KeyError:
            pass

        self.add_default_links_values(dict_report)

        return dict_report

    def format_risk(self, json_response, dict_report):
        """
        Format Risk data from the JSON response and add to the report.

        Args:
            json_response (dict): API response containing entity context
            dict_report (dict): analyzer report content

        Returns:
            dict: the analyzer report content with Risk data
        """
        evidenceDetails = {}
        risk_obj = json_response['data']['risk']

        try:
            riskScore = risk_obj['score']
        except KeyError:
            riskScore = 0

        try:
            evidenceDetails = risk_obj['evidenceDetails']
            evidenceDetails.reverse()
        except KeyError:
            pass

        if not evidenceDetails:
            evidenceDetails = [
                {
                    "criticality": 0,
                    "criticalityLabel": "None",
                    "rule": "No Risk Rules Found",
                    "evidenceString": "No Evidence Details Found",
                }
            ]

        risk_summary = risk_obj['riskSummary']
        criticality = risk_obj['criticality']
        criticality_label = risk_obj['criticalityLabel']

        dict_report['Risk_Score'] = riskScore
        dict_report['Risk_Summary'] = risk_summary
        dict_report['Risk_Details'] = evidenceDetails
        dict_report['Criticality'] = criticality
        dict_report['Criticality_Label'] = criticality_label

        return dict_report

    def build_report(self, json_response, observable):
        """Parse the JSON response from entity enrichment to build the long.html report.

        Args:
            json_response (dict): API response containing entity context
            observable (string): observable enriched with Recorded Future
        """
        ai_insights_obj = json_response['data']['aiInsights']
        if ai_insights_obj['text']:
            ai_insights = ai_insights_obj['text']
        elif ai_insights_obj['comment']:
            ai_insights = ai_insights_obj['comment']
        else:
            ai_insights = "Insufficient Information for Analysis"

        try:
            if self.data_type == URL_DATA_TYPE:
                intel_card = "https://app.recordedfuture.com/live/sc/entity/url%3A" + observable
            else:
                intel_card = json_response['data']['intelCard']
        except KeyError:
            intel_card = "https://app.recordedfuture.com/live/"

        dict_report = {
            'Intel_Card': intel_card,
            'AI_Insights': ai_insights,
        }

        dict_report = self.format_risk(json_response, dict_report)
        dict_report = self.format_related_entities(json_response, dict_report)
        dict_report = self.format_links(json_response, dict_report)

        # ensure_ascii should be set to False, but there appears to be a bug in Cortexutils.
        # Setting True for now.
        self.report(dict_report, True)

    def summary(self, raw):
        """Creates the Observable short summary tag to include the Risk Score and color-coded
        by Criticality.

        Args:
            raw (dict): The long report contents

        Returns:
            dict: The short Summary tag taxonomy
        """
        taxonomies = []
        namespace = "RecordedFuture"
        predicate = "RiskScore"
        level = "safe"
        value = raw['Risk_Score']

        criticality = raw['Criticality']

        if criticality == 1:
            level = "info"
        elif criticality == 2:
            level = "suspicious"
        elif criticality >= 3:
            level = "malicious"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {'taxonomies': taxonomies}

    def run(self):
        """The entry point when the Recorded Future Analyzer is run on an observable."""
        Analyzer.run(self)
        types = [IP_DATA_TYPE, DOMAIN_DATA_TYPE, FQDN_DATA_TYPE, HASH_DATA_TYPE, URL_DATA_TYPE]

        if self.data_type in types:
            observable = self.get_param("data", None, "Data is missing")
            json_response = self.lookup_observable(observable, self.data_type)
            self.build_report(json_response, observable)
        else:
            self.error("Invalid data type")


if __name__ == "__main__":
    RecordedFuture().run()
