#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import os
import subprocess
import argparse
import json
import re
from collections import defaultdict

class CapaAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.capa_path = self.get_param("config.capa_path", "/Cortex-Analyzers/analyzers/Capa/capa")
        self.filepath = self.get_param('file', None, 'File parameter is missing.')
 
    def summary(self, raw):
        taxonomies = []
        level = 'info'
        namespace = 'Capa'

        predicate = 'CapaAnalyze'
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, "analyzed!"))

        return {"taxonomies": taxonomies}

    def run(self):
        parser = argparse.ArgumentParser(description='exec capa.')
        parser.add_argument('filepath', type=str, help='file path')
        args = parser.parse_args()

        if os.path.exists(self.filepath):
            f = subprocess.check_output([self.capa_path, '-j', self.filepath])
            process = json.loads(f)
            rules = process['rules']
            tactics = []
            techniques = []
            subtechniques = []
            ids = []
            capabilities = {}

            for rule in rules:
                try:
                    # Metadata
                    meta = process['rules'][rule]['meta']
                    
                    # ATT&CK details
                    attack = meta['att&ck'][0]
                    
                    # ID
                    id = attack['id']
                    
                    # Technique
                    technique = attack['technique'] + " - " + id
                    
                    # Subtechnique
                    subtechnique = attack['subtechnique']
                    
                    # Tactic
                    tactic = attack['tactic']
                    
                    # Capability
                    capability_name = process['rules'][rule]['meta']['name']

                    if tactic not in tactics:
                        tactics.append(tactic)
                     
                    if subtechnique != "":
                        if subtechnique not in subtechniques: 
                            subtechniques.append(attack['subtechnique'])
                    
                    if technique not in techniques:
                        techniques.append(attack['technique'])
 
                    if id not in ids:
                        ids.append(id)
                    
                    if tactic not in capabilities:
                        capabilities[tactic] = {}

                    if technique not in capabilities[tactic]:
                        capabilities[tactic][technique] = []

                    if capability_name not in capabilities[tactic][technique]:
                        capabilities[tactic][technique].append(capability_name)
                except:
                    continue
        self.report({ 'capabilities': capabilities, 'tactics': tactics, 'techniques': techniques, 'subtechniques': subtechniques, 'ids': ids, 'rules': rules })
if __name__ == '__main__':
    CapaAnalyzer().run()
