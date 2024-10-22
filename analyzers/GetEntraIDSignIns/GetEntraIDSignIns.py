#!/usr/bin/env python3
# encoding: utf-8
# Author: @jahamilto
import requests
import traceback
from datetime import datetime, timedelta
from cortexutils.analyzer import Analyzer

# Initialize Azure Class
class GetEntraIDSignIns(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.client_id = self.get_param('config.client_id', None, 'Microsoft Entra ID Application ID/Client ID Missing')
        self.client_secret = self.get_param('config.client_secret', None, 'Microsoft Entra ID Registered Application Client Secret Missing')
        self.tenant_id = self.get_param('config.tenant_id', None, 'Microsoft Entra ID Tenant ID Mising')
        self.time_range = self.get_param('config.lookup_range', 7)
        self.lookup_limit = self.get_param('config.lookup_limit', 12)
        self.state = self.get_param('config.state', None)
        self.country = self.get_param('config.country', None)


    def run(self):
        Analyzer.run(self)

        if self.data_type == 'mail':
            try:
                self.user = self.get_data()
                if not self.user:
                    self.error("No user supplied")
                

                token_data = {
                    "grant_type": "client_credentials",
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                    'resource': 'https://graph.microsoft.com',
                    'scope': 'https://graph.microsoft.com'
                    }
                
                filter_time = datetime.utcnow() - timedelta(days=self.time_range)
                format_time = str("{}T00:00:00Z".format(filter_time.strftime("%Y-%m-%d")))



                #Authenticate to the graph api 

                redirect_uri = "https://login.microsoftonline.com/{}/oauth2/token".format(self.tenant_id)
                token_r = requests.post(redirect_uri, data=token_data)
                token = token_r.json().get('access_token')

                if token_r.status_code != 200:
                    self.error('Failure to obtain azure access token: {}'.format(token_r.content))

                # Set headers for future requests
                headers = {
                    'Authorization': 'Bearer {}'.format(token)
                }

                base_url = 'https://graph.microsoft.com/v1.0/'
                
                r = requests.get(base_url + "auditLogs/signIns?$filter=startsWith(userPrincipalName,'{}') and createdDateTime ge {}&$top={}".format(self.user, format_time, self.lookup_limit), headers=headers)

                # Check API results
                if r.status_code != 200:
                    self.error('Failure to pull sign ins of user {}: {}'.format(self.user, r.content))
                else:
                    full_json = r.json()['value']

                    new_json = {
                        "filterParameters": None,
                        "signIns": []
                    }

                    # Summary statistics
                    risks = ex_state = ex_country = 0

                    for signin in full_json:

                        success = False

                        details = {}
                        details["signInTime"] = signin["createdDateTime"]
                        details["ip"] = signin["ipAddress"]
                        details["appName"] = signin["appDisplayName"]
                        details["clientApp"] = signin["clientAppUsed"]
                        details["resourceName"] = signin["resourceDisplayName"]
                        # Check how to format status result
                        if signin["status"]["errorCode"] == 0:
                            details["result"] = "Success"
                            success = True
                        else:
                            details["result"] = "Failure: " + signin["status"]["failureReason"]
                        details["riskLevel"] = signin["riskLevelDuringSignIn"]
                        #Increase risk counter
                        if details["riskLevel"] != 'none' and success: risks += 1
                        
                        device = {}
                        device_info = signin["deviceDetail"]
                        device["id"] = "Not Available" if device_info["deviceId"] == "" else device_info["deviceId"]
                        device["deviceName"] = "Not Available" if device_info["displayName"] == "" else device_info["displayName"]
                        device["operatingSystem"] = device_info["operatingSystem"]

                        location = {}
                        location_info = signin["location"]
                        location["city"] = location_info["city"]
                        location["state"] = location_info["state"]
                        if self.state and location["state"] != self.state and success: ex_state += 1
                        location["countryOrRegion"] = location_info["countryOrRegion"]
                        if self.country and location["countryOrRegion"] != self.country and success: ex_country += 1

                         
                        cAC = "None"
                        for policies in signin["appliedConditionalAccessPolicies"]:
                            if policies["result"] == "success":
                                if cAC == 'None':
                                    cAC = policies["displayName"]
                                else:
                                    cAC += (", " + policies["displayName"])
                            

                        new_json["signIns"].append({
                            "id": signin["id"],
                            "basicDetails": dict(details), 
                            "deviceDetails": dict(device), 
                            "locationDetails": dict(location),
                            "appliedConditionalAccessPolicies": cAC
                        })
                    
                    new_json["sum_stats"] = {"riskySignIns": risks, "externalStateSignIns": ex_state, "foreignSignIns": ex_country}
                    new_json["filterParameters"] = "Top {} signins from the last {} days. Displaying {} signins.".format(self.lookup_limit, self.time_range, len(new_json["signIns"]))

                # Build report to return to Cortex
                self.report(new_json)
                                
            except Exception as ex:
                self.error(traceback.format_exc())
                
        else:
            self.error('Incorrect dataType. "mail" expected.')


    def summary(self, raw):
        taxonomies = []

        if len(raw.get('signIns', [])) == 0:
            taxonomies.append(self.build_taxonomy('info', 'EntraIDSignins', 'SignIns', 'None'))
        else:
            taxonomies.append(self.build_taxonomy('safe', 'EntraIDSignins', 'Count', len(raw['signIns'])))

        stats = raw.get("sum_stats", {})
        if stats.get("riskySignIns", 0) != 0:
            taxonomies.append(self.build_taxonomy('suspicious', 'EntraIDSignins', 'Risky', stats["riskySignIns"]))
        if stats.get("externalStateSignIns", 0) != 0:
            taxonomies.append(self.build_taxonomy('suspicious', 'EntraIDSignins', 'OutOfState', stats["externalStateSignIns"]))
        if stats.get("foreignSignIns", 0) != 0:
            taxonomies.append(self.build_taxonomy('malicious', 'EntraIDSignins', 'ForeignSignIns', stats["foreignSignIns"]))

        return {'taxonomies': taxonomies}


if __name__ == '__main__':
    GetEntraIDSignIns().run()
