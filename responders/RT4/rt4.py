#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
from rt import Rt
from rt import ConnectionError
from template import NotificationContext
from config import RT4ResponderConfig
from datetime import datetime
from collections import defaultdict
from defang import defang
import json

class RT4(Responder):

    def __init__(self):
        Responder.__init__(self)
        self.server = self.get_param('config.server', None, 'Missing RT4 server')
        self.server = self.server.rstrip('/')
        self.username = self.get_param('config.username', None, 'Missing RT4 username')
        self.password = self.get_param('config.password', None, 'Missing RT4 password')
        self.tag_to_template_map = self.get_param('config.tag_to_template_map')
        self.thehive_cf_rtticket = self.get_param('config.thehive_cf_rtticket')

        cf_list_tmp = self.get_param('config.custom_field_list', None)

        if cf_list_tmp is not None:
            cf_dict_tmp = {}
            for cf_item in cf_list_tmp:
                if cf_item is not None:
                    cf_name, cf_value = cf_item.split(':', 1)
                    cf_dict_tmp['CF_'+ cf_name] = cf_value
        else:
            cf_dict_tmp = None

        global_config = {
            'Queue': self.get_param('config.Queue', None, 'Missing default queue'),
            'Owner': self.get_param('config.Owner', None),
            'Status': self.get_param('config.Status', None),
            'template': self.get_param('config.template', None)
        }
        global_config.update(cf_dict_tmp)

        # init global config
        self.config = RT4ResponderConfig(weight='global', **global_config)

        # create map for ticket creation arguments that will convert case(capitalization) 
        # to what's expected by rt module
        self.TICKET_ARGS_MAP = {
            'cc': 'Cc',
            'admincc': 'AdminCc',
            'subject': 'Subject',
            'owner': 'Owner',
            'queue': 'Queue',
            'status': 'Status',
            'requestor': 'Requestor',
            'requestors': 'Requestor'
        }

    def run(self):
        Responder.run(self)
        self.instance_type = self.get_param('data._type')
        observable_list = []

        # case observable details
        if self.instance_type == 'case_artifact':
            instance_data = self.get_param('data', None, 'Missing indicator')
            # process case tags first
            case_tags = self.get_param('data.case.tags')
            case_config = self.process_tags(case_tags)
            self.config.update(weight='case', **case_config)


        # case details
        if self.instance_type == 'case':
            """
            api GET for case details don't include references to its observables
            POST to thehive/api/case/artifact/_search with json body
            {
                "query": { "_parent": { "_type": case", "_query": { "_id": "<<CASEID>>" } } },
                "range": "all"
            }
            should return a list of dicts which are populated with k,v characteristic of artifacts.
            """
            import requests
            thehive_url = self.get_param('config.thehive_url', None, """
                Missing URL for TheHive. Must have configured this Responder setting to process Cases.""")
            thehive_token = self.get_param('config.thehive_token', None, """
                Missing API token for TheHive. Must have configured this Responder setting to process Cases.""")
            case_id = self.get_param('data._id')

            payload = {
                "query": { "_parent": { "_type": "case", "_query": { "_id": case_id } } },
                "range": "all"
            }
            headers = { 'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(thehive_token) }
            thehive_api_url_case_search = '{}/api/case/artifact/_search'.format(thehive_url)
            r = requests.post(thehive_api_url_case_search, data=json.dumps(payload), headers=headers)

            if r.status_code != requests.codes.ok:
                self.error(json.dumps(r.text))

            instance_data = r.json()

        # alert details
        if self.instance_type == 'alert':
            instance_data = self.get_param('data.artifacts', None, 'Missing artifacts')

        # process artifact/observable/case tags
        obs_tags = self.get_param('data.tags')
        config_from_tags = self.process_tags(obs_tags)
        self.config.update(weight=self.instance_type, **config_from_tags)
        # only ever have one observable for cases, but could have multiples for other types
        observable_list.extend(self.process_observables(instance_data))
        # should iterate the observable_list and merge the indicator_lists of any observables that share
        # non-differing configs
        observable_list = self.dedupe_and_merge(observable_list)

        # for each ticket creation, log return info to return_info dict in either the 'failures' key is failed,
        # or the 'successes' key (which is a nested dict with k,v where k = rt_ticket # and v = ticket settings)
        self.return_info = defaultdict(list)
        for observable in observable_list:
            new_ticket, rt_ticket_submission = self.create_rt_ticket(observable)
            if new_ticket == -1:
                msg = """RT ticket creation error. Possibly bad data such as non-existent Owner or Queue; 
            or data that does not correspond to an RT field. Observable info: {}""".format(observable)
                self.return_info['failures'].append(msg)
            else:
                msg = """Ticket #{} created in Request Tracker with these settings: 
                    \n{}""".format(new_ticket, rt_ticket_submission)
                ticket_url = self.server + '/Ticket/Display.html?id={}'.format(new_ticket)
                self.return_info['successes'].append({ 'id': new_ticket, 'msg': msg, 'ticket_url': ticket_url })

        if 'successes' not in self.return_info:
            self.error(json.dumps(self.return_info))
        else:
            self.report({'message': json.dumps(self.return_info)})


    def operations(self, raw):
        # if we had any successfully created tickets, get the corresponding RT ticket nums to add to a hive custom field
        # convert 'successes' dict keys (ticket ids) to a list of ints, then ints to strings to join them as csv
        created_tickets = []
        for ticket in self.return_info['successes']:
                created_tickets.append(ticket['ticket_url'])
        created_tickets = ', '.join([str(i) for i in created_tickets])


        if self.instance_type == 'case_artifact':
            return [self.build_operation('AddTagToArtifact', tag='rt4:submitted'), 
                self.build_operation('AddCustomFields', name=self.thehive_cf_rtticket, value=created_tickets, tpe='string')]
        elif self.instance_type == 'alert':
            return [self.build_operation('AddTagToAlert', tag='rt4:submitted'), 
                self.build_operation('AddCustomFields', name=self.thehive_cf_rtticket, value=created_tickets, tpe='string')]
        elif self.instance_type == 'case':
            return [self.build_operation('AddTagToCase', tag='rt4:submitted'),
                self.build_operation('AddCustomFields', name=self.thehive_cf_rtticket, value=created_tickets, tpe='string')]

    def process_observables(self, data):
        observable_list = []
        # if we were handed a single dict instead of a list, make it a list of 1
        if not isinstance(data, list):
            data = [data]
        for i in data:
            # setup a config for each observable
            obs_config_tmp = {
                'indicator_list': [i['data']]
            }
            obs_config_from_tags = self.process_tags(i['tags'])
            # merge all hive data on input object w/ config from tags
            tmp_dict = ({**self.get_param('data'), **obs_config_tmp})
            tmp_dict = ({**tmp_dict, **obs_config_from_tags})
            # tmp_dict = ({**obs_config_tmp, **obs_config_from_tags})
            # merged into a dict but needs to be converted to RT4ResponderConfig obj
            tmp_dict = ({**self.config, **tmp_dict}) 
            observable = RT4ResponderConfig('observable', **tmp_dict)
            observable_list.append(observable)

        return observable_list

    def dedupe_and_merge(self, observable_list):
        """Takes a list of dict observables and removes any duplicates while merging observables where the
        only difference is the indicator (implying that if all other config settings are the same, they can
        be sent in the same RT4 ticket notification).
        Input: list of RT4ResponderConfig objects
        Output: list of deduped/merged RT4ResponderConfig objects
        """ 
        deduped_list = []
        seen = set()
        for item in observable_list:
            h = item.__copy__()
            # pop off indicator_list key so as not to compare that one since if it's diff, we can just merge it later
            h.pop('indicator_list')
            # convert dict to hashable type (tuple, in this case) for comparison
            h = tuple(h.items())
            if h not in seen:
                seen.add(h)
                deduped_list.append(item)
            else:
                for obs in deduped_list:
                    # check item against all observables in observable_list to see if the only diff is 'indicator_list'
                    compare_result = self._dict_compare(item, obs)[2]
                    if len(compare_result) == 1 and 'indicator_list' in compare_result:
                        # if we get here, the obs were the same, so see if value of indicator_list key is unique
                        if item['indicator_list'] not in obs['indicator_list']:
                            obs['indicator_list'].extend(item['indicator_list'])
                        
        return deduped_list

    def process_tags(self, tags):
        processed_tags = {}
        tmpl_tag = None
        template = None
        mail_tags = []
        cc_tags = defaultdict(list)

        for tag in tags:
            # snag any tag used for setting rt4 ticket values and split into name and value 
            # (except requestor which is handled elsewhere)
            if tag.lower().startswith('rt4_set_') and not tag.lower().startswith('rt4_set_requestor'):
                rt_setting_name, rt_setting_value = tag.split('rt4_set_')[1].split(':', 1)
                # handle custom fields if present since the format is slightly different than other args
                if rt_setting_name.lower().startswith('cf_'):
                    cf_name = 'CF_' + rt_setting_name.split('cf_')[1]
                    cf_value = rt_setting_value
                    processed_tags.update({cf_name : cf_value})
                elif rt_setting_name.lower().startswith('template'):
                    tmpl_tag = rt_setting_value
                # cover cc, bcc, or admincc tags
                elif rt_setting_name.lower().endswith('cc'):
                    rt_setting_name = self.TICKET_ARGS_MAP[rt_setting_name]

                    cc_tags[rt_setting_name].append(rt_setting_value)
                else:
                    try:
                        rt_setting_name = self.TICKET_ARGS_MAP[rt_setting_name]
                    except KeyError as e:
                        self.error('One of the rt4_set_ tags was not recognized: {}'.format(e))
                    processed_tags.update({rt_setting_name : rt_setting_value})

            elif tag.lower().startswith('contact:') or tag.lower().startswith('rt4_set_requestor'):
                mail_tags.append(tag.split(':', 1)[1])

            # map tags to a template if:
            # (1) overriding rt4_set_template NOT present and 
            # (2) appropriate match found
            if not tmpl_tag:
                for mapping in self.tag_to_template_map:
                    map_tag, map_template = mapping.split(':', 1)
                    if map_tag == tag:
                        template = map_template
                    # allow overriding of template_name if appropriate rt4_set_template tag was present
            else:
                template = tmpl_tag
        
        # convert list of contacts to comma-separated string
        if mail_tags:
            requestor_list = u', '.join(mail_tags)
            processed_tags.update({'Requestor' : requestor_list})
    
        # convert list of admincc/cc/bcc to comma-separated string and merge into processed_tags
        """processed_tags should be a dict of all tags and values that were processed, e.g.:
        {   "Owner": "root", 
            "CF_Classification": "phishing_generic", 
            "Queue": "Incident Reports", 
            "Requestor": "staff1@dom.org, staff2@dom.org"
        }
        """
        if cc_tags:
            """cc_tags should be a dict of all admincc/bcc/cc tags and values that were processed, e.g.:
            { "AdminCc": "staff3@dom.org, outsider@anotherdom.org" }
            """
            for key, val in cc_tags.items():
                cc_tags[key] = u', '.join(val)
            
            # merge cc_tags into processed_tags
            processed_tags.update(cc_tags)
            
        # see if template var was ever defined above; if not, do nothing; if so, add to dict
        if template is not None:
            processed_tags.update({'template' : template})
            
        return processed_tags

    def create_rt_ticket(self, observable):
        # create an observable config item that will be used to contain all observable and template info
        # to pass along to RT during ticket creation
        obs_config = RT4ResponderConfig(weight='case', **self.config)
        obs_config.update(weight='observable', **observable)
        # defang indicators and write them back as a single string joined together by newlines
        if 'indicator_list' in observable:
            indicator_list = defang(u'\n'.join(observable['indicator_list']))
            observable.update(weight='observable', **{ 'indicator_list': indicator_list} )
        else:
            self.error("""Unable to find indicators on case/alert/observable: 
                {}""".format(json.dumps(observable, indent=1)))

        if 'template' in observable:
            obs_config.update(weight='observable', **{ 'template': observable['template'] })
        if 'template' not in obs_config:
            self.error("""
                Couldn't map a tag to a notification type. 
                Observable/alert/case must be tagged with one 'rt4_set_template:<template_name>' tag, 
                where <template_name> is the name of a file (without .j2 ext) in /templates dir""")
        # render the notification template to be passed on to the observable config item
        rendered_template = NotificationContext().render_blocks_to_dict(
            template_name=obs_config['template'], 
            kwargs=observable
        )
        obs_config.update(weight='template', **rendered_template)

        if 'Requestor' in observable:
            obs_config.update(weight='observable', **{ 'Requestor': observable['Requestor'] })
        if 'Requestor' not in obs_config:
            self.error("""
                Case/alert/observable must be tagged with at least one 'contact:abuse@domain.local' or 
                set_rt4_requestor:abuse@domain.local tag with an appropriate email address""")

         # build session dict
        rt_session = {
            'url': self.server + "/REST/1.0/",
            'default_login': self.username,
            'default_password': self.password
        }

        # create ticket dict
        rt_ticket = {}

        # add additional k,v pairs (as long as it's not the template or indicator_list since those are not accepted
        # as params to the Rt py module for RT ticket creation)
        for key, value in obs_config.items():
            if obs_config[key] is not None and key != 'indicator_list' and key != 'template':
                rt_ticket[key] = value

        # create rt session
        try:
            rt_session = Rt(**rt_session)
            login_ret = rt_session.login()
        except ConnectionError as e:
            self.error("{}".format(e))
        except Exception as e:
            self.error("Error: {}".format(e))
        if login_ret != True:
            self.error('Authentication/Connection error to RT')

        # create ticket
        try:
            new_ticket = rt_session.create_ticket(**rt_ticket)
        except Exception as e:
            rt_session.logout()
            self.error("""RT ticket creation error: {} Possibly bad data such as non-existent Owner or Queue; 
            or data that does not correspond to an RT field. 
            \nSent the following RT request: {}""".format(e, json.dumps(rt_ticket, indent=2)))
        
        rt_session.logout()
        return new_ticket, rt_ticket

    def _dict_compare(self, d1, d2):
        """Feed this function two dictionaries and it can return if there are any differences
        Courtesy of: https://stackoverflow.com/a/18860653
        """
        try:
            d1_keys = set(d1.keys())
            d2_keys = set(d2.keys())
        except:
            self.error("""Could not get keys from dicts for comparison. dict1: 
                {}\ndict2: {}""".format(json.dumps(d1), json.dumps(d2))
            )
        intersect_keys = d1_keys.intersection(d2_keys)
        added = d1_keys - d2_keys
        removed = d2_keys - d1_keys
        modified = {o : [d1[o], d2[o]] for o in intersect_keys if d1[o] != d2[o]}
        same = set(o for o in intersect_keys if d1[o] == d2[o])
        return added, removed, modified, same

def _flatten(arr: list):
    """ Flattens arbitrarily-nested list `arr` into single-dimensional. 
    Courtesy of: https://stackoverflow.com/a/54306091
    """
    while arr:
        if isinstance(arr[0], list):  # Checks whether first element is a list
            arr = arr[0] + arr[1:]  # If so, flattens that first element one level
        else:
            yield arr.pop(0)  # Otherwise yield as part of the flat array

if __name__ == '__main__':
    RT4().run()
