#!/usr/bin/env python3
# encoding: utf-8
# Author: Florian Perret (@cyberpescadito)

from mdutils import MdUtils
import pdfkit
from cortexutils.responder import Responder
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseTask, CaseTaskLog, CustomFieldHelper
import requests
import json
import time
import os
from datetime import datetime

class case_reporter(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.thehive_url = self.get_param('config.thehive_url', None, "TheHive URL is missing")
        self.thehive_apikey = self.get_param('config.thehive_apikey', None, "TheHive API key is missing")
        self.temp_path = self.get_param('config.temp_path', None, "missing temporary files path location")
        self.max_observables_tlp = self.get_param('config.max_observables_tlp')
        self.section_information = self.get_param('config.section_information')
        self.section_description = self.get_param('config.section_description')
        self.section_customFields = self.get_param('config.section_customFields')
        self.section_summary = self.get_param('config.section_summary')
        self.section_observables = self.get_param('config.section_observables')
        self.section_ttps = self.get_param('config.section_ttps')
        self.section_tasks = self.get_param('config.section_tasks')
        self.section_tasklogs = self.get_param('config.section_tasklogs')
        self.export_format = self.get_param('config.export_format')
        self.branding = self.get_param('config.branding_logo')
        self.caseId = self.get_param('data.id')
        self.api = TheHiveApi(self.thehive_url, self.thehive_apikey, version=4)

    def mdConstruction(self, mycase, translated_values,hive_url,h,sorted_sections,max_observables_tlp,logo_insertion):
        #Filename and Title
        mdFile = MdUtils(file_name="Case #" + str(mycase['caseId']), title= logo_insertion + " Case #" + str(mycase['caseId']) + " - " + str(mycase['title']))
        mdFile.new_line("___")

        #Case overview
        mdFile.new_header(level=1, title='Case overview')
        mdFile.new_line("___")

        #Loop to append the section in the defined order
        #Avoid unwanted sections by skipping 0
        for i in range (1,8):
            #Case details
            if 'information' in sorted_sections and i == sorted_sections['information']:
                mdFile.new_header(level=2, title='Information')
                mdFile.new_line("**Title:** " + mycase['title'])
                mdFile.new_line("**Severity:** ")
                mdFile.write(translated_values['severity'], color=translated_values['severity_color'])
                mdFile.new_line("**TLP:** ")
                mdFile.write(translated_values['tlp'], color=translated_values['tlp_color'])
                mdFile.new_line("**PAP:** ")
                mdFile.write(translated_values['pap'], color=translated_values['pap_color'])
                mdFile.new_line("**Assignee:** " + mycase['owner'])
                mdFile.new_line("**Incident start time:** " + translated_values['startDate'])
                mdFile.new_line("**Case creation time:** " + translated_values['createdAt'])
                if mycase['status'] == "Resolved":
                    mdFile.new_line("**Case close time:** " + translated_values['endDate'])

                mdFile.new_line("___")

            #Case description
            if 'description' in sorted_sections and sorted_sections['description'] == i:
                mdFile.new_header(level=2, title='Description')
                mdFile.new_line(mycase['description'])
                mdFile.new_line("___")
            #Case customFields
            if 'customFields' in sorted_sections and sorted_sections['customFields'] == i:
                mdFile.new_header(level=2, title='Additional information')
                for cf, value in mycase['customFields'].items():
                    if 'string' in value:
                        cfvalue = value['string']
                    elif 'integer' in value:
                        cfvalue = str(value['integer'])
                    elif 'boolean' in value:
                        cfvalue = str(value['boolean'])
                    elif 'date' in value:
                        cfvalue = str(value['date'])
                    elif 'float' in value:
                        cfvalue = str(value['float'])

                    cfline = ('**' + cf + ":** " + str(cfvalue))
                    mdFile.new_line(cfline)
                mdFile.new_line("___")

            #Case summary
            if 'summary' in sorted_sections and sorted_sections['summary'] == i:
                if 'summary' in mycase and mycase['summary'] is not None:
                    mdFile.new_header(level=2, title='Summary')
                    mdFile.new_line(mycase['summary'])
                    mdFile.new_line("___")

            #Case observables
            if 'observables' in sorted_sections and sorted_sections['observables'] == i:
                table_case_observables = self.create_table_case_observables(self.api,mycase,hive_url,h,max_observables_tlp)
                mdFile.new_header(level=2, title='Observables')
                mdFile.new_table(columns=6, rows=int(table_case_observables.__len__()/6), text=table_case_observables, text_align='left')
                mdFile.new_line("___")

            #Case TTPs
            if 'ttps' in sorted_sections and sorted_sections['ttps'] == i:
                case_ttps = self.create_case_ttps_table(mycase,hive_url,h)
                mdFile.new_header(level=2, title='TTPs')
                mdFile.new_table(columns=3, rows=int(case_ttps.__len__()/3), text=case_ttps, text_align='left')
                mdFile.new_line("___")

            #Case tasks
            if 'tasks' in sorted_sections and sorted_sections['tasks'] == i:
                mdFile.new_header(level=1, title='Tasks')
                case_tasks = self.create_case_tasks(self.api,mycase,hive_url,h)

                #This var aim to know if we changed of task group or not since the previous task.
                last_task_group = None
                #Considering every task
                for task in case_tasks:
                    if task['group']  != last_task_group:
                        last_task_group = task['group']
                        mdFile.new_header(level=2, title= '[' + task['group'] + '] ')
                    
                    mdFile.new_header(level=3, title=task['title'])
                    mdFile.new_line("**Status:** " + task['status'])
                    if 'startDate' in task:
                        mdFile.new_line("**Start date:** " + self.epoch_to_human(task['startDate']))
                    if 'assignee' in task and len(task['assignee']) > 0:
                        mdFile.new_line("**Assigned to:** " + task['assignee'])
                    else:
                        mdFile.new_line("**Assigned to:** Unassigned")
                    if 'description' in task:
                        mdFile.new_line("**Description:** " + task['description'])
                    if 'tasklogs' in sorted_sections and sorted_sections['tasklogs'] > 0:
                        if 'log' in task:
                            if len(task['log']) > 0:
                                #Unhappy with heading level 3 (too close of 2), library doesn't support usual new_header with level > 3, cheating a bit
                                mdFile.new_line("#### Task log(s):")
                                #Considering every task log in the task
                                for log in task['log']:
                                    #detect and remove md code that would break the report formatting
                                    log_message = str(log['message'])
                                    safe_log_message = log_message.replace("``", "")
                                    mdFile.new_line('**[' + self.epoch_to_human(log['date']) + '] ' + log['owner'] + ":** ")
                                    mdFile.new_line("")
                                    mdFile.new_line("```")
                                    mdFile.new_line(safe_log_message)
                                    mdFile.new_line("```")
                                    mdFile.new_line("")
                    mdFile.new_line("___")
        #File generation
        mdFile.new_line("Automatically generated at " + str(datetime.now()) + " by Case Reporter responder, by StrangeBee (c) all rights reserved.", align='right')
        mdFile.create_md_file()

    def translations(self, mycase):
        #returned object will contains: severity, tlp, pap, createdAt, startDate, endDate
        translated_values = {}

        #Severity
        if mycase['severity'] == 1:
            translated_values['severity'] = "Low"
            translated_values['severity_color'] = "deepskyblue"
        elif mycase['severity'] == 2:
            translated_values['severity'] = "Medium"
            translated_values['severity_color'] = "orange"
        elif mycase['severity'] == 3:
            translated_values['severity'] = "High"
            translated_values['severity_color'] = "red"
        elif mycase['severity'] == 4:
            translated_values['severity'] = "Critical"
            translated_values['severity_color'] = "darkred"

        #TLP
        if mycase['tlp'] == 1:
            translated_values['tlp'] = "Green"
            translated_values['tlp_color'] = "limegreen"
        elif mycase['tlp'] == 2:
            translated_values['tlp'] = "Amber"
            translated_values['tlp_color'] = "orange"
        elif mycase['tlp'] == 3:
            translated_values['tlp'] = "Red"
            translated_values['tlp_color'] = "red"
        elif mycase['tlp'] == 0:
            translated_values['tlp'] = "White"
            translated_values['tlp_color'] = "deepskyblue"

        #PAP
        if mycase['pap'] == 1:
            translated_values['pap'] = "Green"
            translated_values['pap_color'] = "limegreen"
        elif mycase['pap'] == 2:
            translated_values['pap'] = "Amber"
            translated_values['pap_color'] = "orange"
        elif mycase['pap'] == 3:
            translated_values['pap'] = "Red"
            translated_values['pap_color'] = "red"
        elif mycase['pap'] == 0:
            translated_values['pap'] = "White"
            translated_values['pap_color'] = "deepskyblue"

        #Epoch to human
        if 'createdAt' in mycase:
            translated_values['createdAt'] = self.epoch_to_human(mycase['createdAt'])
        if 'startDate' in mycase:
            translated_values['startDate'] = self.epoch_to_human(mycase['startDate'])
        if mycase['endDate'] is not None:
            translated_values['endDate'] = self.epoch_to_human(mycase['endDate'])
        return translated_values

    def epoch_to_human(self, epoch):
        human = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(epoch)/1000))
        return human

    def create_table_case_observables(self,api,mycase,hive_url,h,max_observables_tlp):
        #Get the observables from TheHive
        mypayload = {"query":[{"_name":"getCase","idOrName":str(mycase['caseId'])},{"_name":"observables"},{"_name":"sort","_fields":[{"_createdAt":"asc"}]},{"_name":"page","from":0,"to":15,"extraData":["seen","permissions","shareCount"]}]}
        r=requests.post(hive_url + '/api/v1/query?name=observables', headers=h, json=mypayload)
        sorted_case_observables = json.loads(r.text)
        #Define table headers
        table_observables = ['data type', 'data', 'IOC', 'sighted', 'Added date','tlp']
        #Build the table
        for observable in sorted_case_observables:
            if max_observables_tlp > observable['tlp']:
                table_observables.append(observable['dataType'])
                if observable['dataType'] == 'file':
                    table_observables.append(str(observable['attachment']['name']))
                else:
                    table_observables.append(str(observable['data'].replace('\n','<br>').replace('.','[.]').replace('http','hxxp')))
                table_observables.append(observable['ioc'])
                table_observables.append(observable['sighted'])
                table_observables.append(self.epoch_to_human(observable['_createdAt']))
                if observable['tlp'] == 0:
                    table_observables.append('White')
                elif observable['tlp'] == 1:
                    table_observables.append('Green')
                elif observable['tlp'] == 2:
                    table_observables.append('Amber')
                elif observable['tlp'] == 3:
                    table_observables.append('Red')
        return table_observables

    def create_case_tasks(self,api,mycase,hive_url,h):
        #Get the case tasks
        payload = {"query":[{"_name":"getCase","idOrName":str(mycase['caseId'])},{"_name":"tasks"},{"_name":"filter","_ne":{"_field":"status","_value":"Cancel"}},{"_name":"sort","_fields":[{"group":"asc"},{"order":"asc"},{"startDate":"asc"},{"title":"asc"}]},{"_name":"page","from":0,"to":15,"extraData":["shareCount","actionRequired"]}]}
        r=requests.post(hive_url + '/api/v1/query?name=case-tasks', headers=h, json=payload)
        case_tasks = json.loads(r.text)

        #Enrich the task with associated task logs
        for task in case_tasks:
            payload = {"query":[{"_name":"getTask","idOrName":task['_id']},{"_name":"logs"},{"_name":"sort","_fields":[{"date":"desc"}]},{"_name":"page","from":0,"to":50,"extraData":["actionCount"]}]}
            r=requests.post(hive_url + '/api/v1/query?name=case-task-logs', headers=h, json=payload)
            if len(r.text) > 0:
                task_logs = json.loads(r.text)
                task['log'] = []
                for log in task_logs:
                    task_log_id = log['_id']
                    task['log'].append(log)
        return case_tasks

    def create_case_ttps_table(self,mycase,hive_url,h):
        #Get the TTPs from TheHive
        payload = {"query":[{"_name":"getCase","idOrName":str(mycase['caseId'])},{"_name":"procedures"},{"_name":"sort","_fields":[{"occurDate":"desc"}]},{"_name":"page","from":0,"to":15,"extraData":["pattern","patternParent"]}]}
        r=requests.post(hive_url + '/api/v1/query?name=case-procedures', headers=h, json=payload)
        case_ttps = json.loads(r.text)
        #Define TTPs table headers
        ttps_table = ['Tactic', 'Technique', 'Occur Date']
        for ttp in case_ttps:
            ttps_table.append(ttp['tactic'])
            if 'patternParent' in ttp['extraData'] and ttp['extraData']['patternParent'] is not None:
                full_technique = "["+ str(ttp['patternId']) + "](" + ttp['extraData']['pattern']['url'] + ") - " + ttp['extraData']['patternParent']['name'] + ":" + ttp['extraData']['pattern']['name']
            else:
                full_technique = "["+ (str(ttp['patternId']) + "](" + ttp['extraData']['pattern']['url'] + ") - " + ttp['extraData']['pattern']['name'])
            ttps_table.append(full_technique)
            ttps_table.append(self.epoch_to_human(ttp['occurDate']))
        return ttps_table

    def create_report_task(self,caseId,mycase,h):
        responder_report = {}
        task = self.api.create_case_task(caseId, CaseTask(
            title = 'Case Reports'))

        if task.status_code == 201:
            responder_report['task_creation'] = 'OK'
            if self.export_format == 'all':
                task_json = json.loads(task.text)
                task_log_md = self.api.create_task_log(task_json['id'], CaseTaskLog(
                    message = "Markdown case report",
                    file = ("Case #" + str(mycase['caseId']) + ".md")))
                if task_log_md.status_code == 201:
                    responder_report['md_file'] = 'OK'
                    os.remove("Case #" + str(mycase['caseId']) + ".md")
                else:
                    responder_report['md_file'] = 'NOK'


                task_log_html = self.api.create_task_log(task_json['id'], CaseTaskLog(
                    message = "HTML case report",
                    file = ("Case #" + str(mycase['caseId']) + ".html")))
                if task_log_html.status_code == 201:
                    responder_report['html_file'] = 'OK'
                    os.remove("Case #" + str(mycase['caseId']) + ".html")
                else:
                    responder_report['html_file'] = 'NOK'


                task_log_pdf = self.api.create_task_log(task_json['id'], CaseTaskLog(
                    message = "Markdown case report",
                    file = ("Case #" + str(mycase['caseId']) + ".pdf")))
                if task_log_md.status_code == 201:
                    responder_report['pdf_file'] = 'OK'
                    os.remove("Case #" + str(mycase['caseId']) + ".pdf")
                else:
                    responder_report['pdf_file'] = 'NOK'
            else:
                task_json = json.loads(task.text)
                task_log_md = self.api.create_task_log(task_json['id'], CaseTaskLog(
                    message = str(self.export_format) + " case report",
                    file = ("Case #" + str(mycase['caseId']) + "." + str(self.export_format))))
                if task_log_md.status_code == 201:
                    responder_report['file_export'] = 'OK'
                    os.remove("Case #" + str(mycase['caseId']) + "." + str(self.export_format))
                else:
                    responder_report['file_export'] = 'NOK'                

            response = requests.patch(self.thehive_url + '/api/case/task/' + str(task_json['id']), headers=h, json={'status':'Completed'})

            return responder_report
        else:
            self.error('Failed to create the task')

    def run(self):
        #TheHive & Authentication
        api = TheHiveApi(self.thehive_url, self.thehive_apikey, version=4)
        h = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.thehive_apikey}

        #TheHive logo/Branding
        if len(self.branding) < 30:
            hive_logo = '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'
        else:
            hive_logo = self.branding
        logo_insertion = '![thehive_logo](data:image/png;base64,' + hive_logo + ')'


        #Get the case
        response = api.get_case(self.caseId)
        if response.status_code >= 400:
            self.error('failed to get the case, error status code: ' + str(response.status_code))
        mycase = json.loads(response.text)

        #Sections activation & sorting
        sorted_sections = {
            'information': self.section_information,
            'description': self.section_description,
            'customFields': self.section_customFields,
            'summary': self.section_summary,
            'observables': self.section_observables,
            'ttps': self.section_ttps,
            'tasks': self.section_tasks,
            'tasklogs': self.section_tasklogs
        }

        #Control max_observables_tlp setting and set default value if the parameter is not or incorrectly set
        if self.max_observables_tlp < 5 and self.max_observables_tlp > 0 or self.max_observables_tlp is None:
            max_observables_tlp = self.max_observables_tlp
        else:
            max_observables_tlp = 3
        #Main
        os.chdir(self.temp_path)
        translated_values = self.translations(mycase)
        self.mdConstruction(mycase,translated_values,self.thehive_url,h,sorted_sections,max_observables_tlp,logo_insertion)
        os.system("md2html -f -o 'Case #" + str(mycase['caseId']) + ".html' 'Case #" + str(mycase['caseId']) + ".md'")
        pdfkit.from_file("Case #" + str(mycase['caseId']) + ".html", "Case #" + str(mycase['caseId']) + ".pdf")
        responder_report = self.create_report_task(str(mycase['caseId']),mycase,h)

        #following parameters, defining the report to provide
        if self.export_format == 'all':
            report_str = ('file upload: MD: ' + responder_report['md_file'] + ', HTML: ' + responder_report['html_file'] + ', PDF: ' + responder_report['pdf_file'])
        else:
            report_str = ('file upload: ' + responder_report['file_export'])
        
        self.report({'report': report_str})

if __name__ == '__main__':
    case_reporter().run()
