#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import os
import subprocess
import json

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
        if not os.path.isfile(self.capa_path) or not os.access(self.capa_path, os.X_OK):
            self.error(f"capa binary not found or not executable at path: {self.capa_path}")
            return

        if not os.path.exists(self.filepath):
            self.error(f"File not found: {self.filepath}")
            return

        try:
            result = subprocess.run(
                [self.capa_path, '-j', self.filepath],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                self.error(f"capa execution failed with return code {result.returncode}: {result.stderr}")
                return
        except Exception as e:
            self.error(f"An error occurred while executing capa: {e}")
            return

        try:
            process = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            self.error(f"Failed to parse capa output as JSON: {e}")
            return
            
        rules = process.get('rules', {})
        tactics = []
        techniques = []
        subtechniques = []
        ids = []
        capabilities = {}

        for rule_key, rule_value in rules.items():
            try:
                # Metadata
                meta = rule_value['meta']

                # ATT&CK details
                attack = meta['att&ck'][0]

                # ID
                attack_id = attack['id']

                # Technique
                technique = f"{attack['technique']} - {attack_id}"

                # Subtechnique
                subtechnique = attack.get('subtechnique', '')

                # Tactic
                tactic = attack['tactic']

                # Capability
                capability_name = meta['name']

                # Collect data
                if tactic not in tactics:
                    tactics.append(tactic)

                if subtechnique:
                    if subtechnique not in subtechniques:
                        subtechniques.append(subtechnique)

                if technique not in techniques:
                    techniques.append(technique)

                if attack_id not in ids:
                    ids.append(attack_id)

                if tactic not in capabilities:
                    capabilities[tactic] = {}

                if technique not in capabilities[tactic]:
                    capabilities[tactic][technique] = []

                if capability_name not in capabilities[tactic][technique]:
                    capabilities[tactic][technique].append(capability_name)
            except KeyError as e:
                #self.error(f"KeyError processing rule {rule_key}: {e}")
                continue
            except Exception as e:
                #self.error(f"Unexpected error processing rule {rule_key}: {e}")
                continue

        self.report({
            'capabilities': capabilities,
            'tactics': tactics,
            'techniques': techniques,
            'subtechniques': subtechniques,
            'ids': ids,
            'rules': rules
        })
    
if __name__ == '__main__':
    CapaAnalyzer().run()
