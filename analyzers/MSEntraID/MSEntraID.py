#!/usr/bin/env python3
# encoding: utf-8
# Author: @jahamilto; nusatanra-self, StrangeBee
import requests
import traceback
from datetime import datetime, timedelta
from cortexutils.analyzer import Analyzer
import re
#import json

# Initialize Azure Class
class MSEntraID(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.client_id = self.get_param('config.client_id', None, 'Microsoft Entra ID Application ID/Client ID Missing')
        self.client_secret = self.get_param('config.client_secret', None, 'Microsoft Entra ID Registered Application Client Secret Missing')
        self.tenant_id = self.get_param('config.tenant_id', None, 'Microsoft Entra ID Tenant ID Mising')
        self.time_range = self.get_param('config.lookup_range', 7)
        self.lookup_limit = self.get_param('config.lookup_limit', 12)
        self.state = self.get_param('config.state', None)
        self.country = self.get_param('config.country', None)
        self.service = self.get_param('config.service', None)
        self.params_list = self.get_param('config.params_list', [])

    def authenticate(self):
        token_data = {
            "grant_type": "client_credentials",
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://graph.microsoft.com/.default'
        }

        redirect_uri = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        token_r = requests.post(redirect_uri, data=token_data)

        if token_r.status_code != 200:
            self.error(f'Failure to obtain Azure access token: {token_r.content}')

        return token_r.json().get('access_token')

    def resolve_user_guid(self, email, headers, base_url):
        """Resolves a userPrincipalName (email) to an objectId (GUID) using direct lookup (most compatible)."""
        url = f"{base_url}users/{email}?$select=id"
        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            self.error(f"Failed to resolve GUID for user {email}: {response.content}")

        user = response.json()
        user_id = user.get("id")
        if not user_id:
            self.error(f"ID not found in response for {email}")

        return user_id

    def ensure_user_guid(self, base_url, headers):
        if "@" in self.user:
            return self.resolve_user_guid(self.user, headers, base_url)
        return self.user

    def handle_get_signins(self, headers, base_url):
        """
        Retrieve sign-in logs for a userPrincipalName within a specified time range.
        """
        if self.data_type != 'mail':
            self.error('Incorrect dataType. "mail" expected.')

        try:
            self.user = self.get_data()
            if not self.user:
                self.error("No user supplied")
            self.guid = self.ensure_user_guid(base_url, headers)
            
            # Build the filter time
            filter_time = datetime.utcnow() - timedelta(days=self.time_range)
            format_time = filter_time.strftime('%Y-%m-%dT00:00:00Z')

            # Query sign-in logs
            endpoint = (
                f"auditLogs/signIns?$filter=userId eq '{self.guid}'"
                f"and createdDateTime ge {format_time}&$top={self.lookup_limit}"
            )
            r = requests.get(base_url + endpoint, headers=headers)

            if r.status_code != 200:
                self.error(f"Failure to pull sign-ins for user {self.user}: {r.content}")

            signins_data = r.json().get('value', [])

            new_json = {
                "filterParameters": None,
                "signIns": []
            }

            # Counters for summary
            risks = 0
            ex_state = 0
            ex_country = 0

            for signin in signins_data:
                # Basic details
                basic_details = {}
                basic_details["signInTime"] = signin.get("createdDateTime", "N/A")
                basic_details["ip"] = signin.get("ipAddress", "N/A")
                basic_details["appName"] = signin.get("appDisplayName", "N/A")
                basic_details["clientApp"] = signin.get("clientAppUsed", "N/A")
                basic_details["resourceName"] = signin.get("resourceDisplayName", "N/A")

                # Determine success/failure
                success = False
                status_info = signin.get("status", {})
                if status_info.get("errorCode") == 0:
                    basic_details["result"] = "Success"
                    success = True
                else:
                    failure_reason = status_info.get("failureReason", "")
                    basic_details["result"] = f"Failure: {failure_reason}" if failure_reason else "Failure"

                # Risk level - 	The risk level during sign-in. Possible values: none, low, medium, high, or hidden. The value hidden means the user or sign-in was not enabled for Azure AD Identity Protection. 
                basic_details["riskLevel"] = signin.get("riskLevelDuringSignIn", "none")
                if basic_details["riskLevel"] in ["low", "medium", "high"] and success:
                    risks += 1

                # Device details
                device_info = signin.get("deviceDetail", {})
                device_details = {
                    "id": device_info.get("deviceId") or "Not Available",
                    "deviceName": device_info.get("displayName") or "Not Available",
                    "operatingSystem": device_info.get("operatingSystem", "N/A")
                }

                # Location details
                location_info = signin.get("location", {})
                location_details = {
                    "city": location_info.get("city", "N/A"),
                    "state": location_info.get("state", "N/A"),
                    "countryOrRegion": location_info.get("countryOrRegion", "N/A")
                }

                # If sign-in was successful, check if it differs from specified state/country
                if success:
                    actual_state = location_details.get("state", "").strip().lower()
                    expected_state = (self.state or "").strip().lower()

                    actual_country = location_details.get("countryOrRegion", "").strip().lower()
                    expected_country = (self.country or "").strip().lower()

                    if expected_state and actual_state and actual_state != expected_state:
                        ex_state += 1

                    if expected_country and actual_country and actual_country != expected_country:
                        ex_country += 1


                # Applied Conditional Access Policies
                applied_policies = signin.get("appliedConditionalAccessPolicies", [])
                cAC = "None"
                for pol in applied_policies:
                    if pol.get("result") == "success":
                        policy_name = pol.get("displayName", "Unknown")
                        if cAC == "None":
                            cAC = policy_name
                        else:
                            cAC += f", {policy_name}"

                new_json["signIns"].append({
                    "id": signin.get("id", "N/A"),
                    "basicDetails": basic_details,
                    "deviceDetails": device_details,
                    "locationDetails": location_details,
                    "appliedConditionalAccessPolicies": cAC
                })

            # Summary stats
            new_json["sum_stats"] = {
                "riskySignIns": risks,
                "externalStateSignIns": ex_state,
                "foreignSignIns": ex_country
            }

            new_json["filterParameters"] = (
                f"Top {self.lookup_limit} signins from the last {self.time_range} days. "
                f"Displaying {len(new_json['signIns'])} signins."
            )

            self.report(new_json)

        except Exception as ex:
            self.error(traceback.format_exc())

    def handle_get_userinfo(self, headers, base_url):
        """Fetch comprehensive user information from Microsoft Entra ID, including manager, license details, and group memberships."""
        if self.data_type != 'mail':
            self.error('Incorrect dataType. "mail" expected.')

        try:
            self.user = self.get_data()
            if not self.user:
                self.error("No user supplied")
            
            self.guid = self.ensure_user_guid(base_url, headers)
            # Use select to retrieve many user attributes. Adjust as needed.
            params = {
                        "$select": ",".join(self.params_list)
                    }

            user_info_url = f"{base_url}users/{self.guid}"
#            user_info_url = f"{base_url}users/{self.user}"

            user_response = requests.get(user_info_url, headers=headers, params=params)

            if user_response.status_code != 200:
                self.error(f"Failed to fetch user info: {user_response.content}")

            user_data = user_response.json()

            # Construct user details dictionary
            user_details = {
                "businessPhones": user_data.get("businessPhones", []),
                "givenName": user_data.get("givenName", "N/A"),
                "surname": user_data.get("surname", "N/A"),
                "displayName": user_data.get("displayName", "N/A"),
                "jobTitle": user_data.get("jobTitle", "N/A"),
                "mail": user_data.get("mail", "N/A"),
                "mobilePhone": user_data.get("mobilePhone", "N/A"),
                "officeLocation": user_data.get("officeLocation", "N/A"),
                "department": user_data.get("department", "N/A"),
                "accountEnabled": user_data.get("accountEnabled", "N/A"),
                "onPremisesSyncEnabled": user_data.get("onPremisesSyncEnabled", "N/A"),
                "onPremisesLastSyncDateTime": user_data.get("onPremisesLastSyncDateTime", "N/A"),
                "onPremisesSecurityIdentifier": user_data.get("onPremisesSecurityIdentifier", "N/A"),
                "proxyAddresses": user_data.get("proxyAddresses", []),
                "usageLocation": user_data.get("usageLocation", "N/A"),
                "userType": user_data.get("userType", "N/A"),
                "userPrincipalName": user_data.get("userPrincipalName", "N/A"),
                "createdDateTime": user_data.get("createdDateTime", "N/A"),
                "lastSignInDateTime": user_data.get("signInActivity", {}).get("lastSignInDateTime", "N/A"),
                "manager": None,  # to be populated below
                "assignedLicenses": [],  # to be populated via licenseDetails
                "memberOf": []
            }

            # Fetch user's manager
            manager_url = f"{base_url}users/{self.guid}/manager?$select=id,displayName,userPrincipalName"
            manager_resp = requests.get(manager_url, headers=headers)
            if manager_resp.status_code == 200:
                manager_data = manager_resp.json()
                # Check if we actually got a manager object
                if not manager_data.get("error"):
                    user_details["manager"] = {
                        "id": manager_data.get("id", "N/A"),
                        "displayName": manager_data.get("displayName", "N/A"),
                        "userPrincipalName": manager_data.get("userPrincipalName", "N/A")
                    }
            
            # Fetch user's license details
            license_url = f"{base_url}users/{self.guid}/licenseDetails"
            license_resp = requests.get(license_url, headers=headers)
            if license_resp.status_code == 200:
                license_data = license_resp.json().get("value", [])
                # Each item in license_data has info about assignedLicenses
                # We can store them or parse them further.
                for lic in license_data:
                    user_details["assignedLicenses"].append({
                        "skuId": lic.get("skuId", "N/A"),
                        "skuPartNumber": lic.get("skuPartNumber", "N/A"),
                        "servicePlans": lic.get("servicePlans", [])
                    })

            # Fetch user's group memberships
            member_of_url = f"{base_url}users/{self.guid}/memberOf"
            member_of_response = requests.get(member_of_url, headers=headers)
            if member_of_response.status_code == 200:
                memberships = member_of_response.json().get("value", [])
                for group in memberships:
                    user_details["memberOf"].append({
                        "id": group.get("id", "N/A"),
                        "displayName": group.get("displayName", "Unknown")
                    })

            # MFA Methods
            mfa_url = f"{base_url}users/{self.guid}/authentication/methods"
            mfa_r = requests.get(mfa_url, headers=headers)

            if mfa_r.status_code == 200:
                mfa_data = mfa_r.json().get("value", [])
                mfa_methods = []

                for method in mfa_data:
                    method_odata_type = method.get("@odata.type", "").lower()
                    
                    # Default structure
                    parsed_method = {
                        "id": method.get("id", "N/A"),
                        "odataType": method_odata_type,    # Full OData type
                        "methodType": "Unknown"
                    }

                    if "phoneauthenticationmethod" in method_odata_type:
                        # https://learn.microsoft.com/en-us/graph/api/resources/phoneauthenticationmethod
                        parsed_method["methodType"]      = "phone"
                        parsed_method["phoneNumber"]      = method.get("phoneNumber", "N/A")
                        parsed_method["phoneType"]        = method.get("phoneType", "N/A")
                        parsed_method["smsSignInState"]   = method.get("smsSignInState", "N/A")
                        parsed_method["isDefault"]        = method.get("isDefault", "N/A")

                    elif "microsoftauthenticatorauthenticationmethod" in method_odata_type:
                        # https://learn.microsoft.com/en-us/graph/api/resources/microsoftauthenticatorauthenticationmethod
                        parsed_method["methodType"]                 = "microsoftAuthenticator"
                        parsed_method["displayName"]                = method.get("displayName", "N/A")
                        parsed_method["deviceTag"]                  = method.get("deviceTag", "N/A")
                        parsed_method["phoneAppVersion"]            = method.get("phoneAppVersion", "N/A")
                        parsed_method["isDefault"]                  = method.get("isDefault", "N/A")
                        parsed_method["isRegisteredForPasswordless"] = method.get("isRegisteredForPasswordless", "N/A")

                    elif "passwordlessmicrosoftauthenticatorauthenticationmethod" in method_odata_type:
                        # https://learn.microsoft.com/en-us/graph/api/resources/passwordlessmicrosoftauthenticatorauthenticationmethod
                        parsed_method["methodType"]                 = "passwordlessMicrosoftAuthenticator"
                        parsed_method["displayName"]                = method.get("displayName", "N/A")
                        parsed_method["deviceTag"]                  = method.get("deviceTag", "N/A")
                        parsed_method["phoneAppVersion"]            = method.get("phoneAppVersion", "N/A")
                        parsed_method["isDefault"]                  = method.get("isDefault", "N/A")
                        parsed_method["isRegisteredForPasswordless"] = method.get("isRegisteredForPasswordless", "N/A")

                    elif "fido2authenticationmethod" in method_odata_type:
                        # https://learn.microsoft.com/en-us/graph/api/resources/fido2authenticationmethod
                        parsed_method["methodType"]                 = "fido2"
                        parsed_method["displayName"]                = method.get("displayName", "N/A")
                        parsed_method["aaGuid"]                     = method.get("aaGuid", "N/A")
                        parsed_method["attestationCertificates"]    = method.get("attestationCertificates", [])
                        parsed_method["attestationLevel"]           = method.get("attestationLevel", "N/A")
                        parsed_method["createdDateTime"]            = method.get("createdDateTime", "N/A")
                        parsed_method["isSelfServiceRegistration"]  = method.get("isSelfServiceRegistration", "N/A")
                        parsed_method["isSystemProtected"]          = method.get("isSystemProtected", "N/A")

                    elif "windowshelloforbusinessauthenticationmethod" in method_odata_type:
                        # https://learn.microsoft.com/en-us/graph/api/resources/windowshelloforbusinessauthenticationmethod
                        parsed_method["methodType"]         = "windowsHelloForBusiness"
                        parsed_method["displayName"]         = method.get("displayName", "N/A")
                        parsed_method["keyStrength"]         = method.get("keyStrength", "N/A")
                        parsed_method["creationDateTime"]    = method.get("creationDateTime", "N/A")
                        parsed_method["isDefault"]           = method.get("isDefault", "N/A")
                        parsed_method["isSystemProtected"]   = method.get("isSystemProtected", "N/A")

                    elif "emailauthenticationmethod" in method_odata_type:
                        # https://learn.microsoft.com/en-us/graph/api/resources/emailauthenticationmethod
                        parsed_method["methodType"]   = "email"
                        parsed_method["emailAddress"] = method.get("emailAddress", "N/A")

                    elif "softwareoathauthenticationmethod" in method_odata_type:
                        # https://learn.microsoft.com/en-us/graph/api/resources/softwareoathauthenticationmethod
                        parsed_method["methodType"]      = "softwareOath"
                        parsed_method["secretKey"]       = method.get("secretKey", "N/A")
                        parsed_method["creationDateTime"] = method.get("createdDateTime", "N/A")

                    elif "temporaryaccesspassauthenticationmethod" in method_odata_type:
                        # https://learn.microsoft.com/en-us/graph/api/resources/temporaryaccesspassauthenticationmethod
                        parsed_method["methodType"]       = "temporaryAccessPass"
                        parsed_method["startDateTime"]    = method.get("startDateTime", "N/A")
                        parsed_method["createdDateTime"]  = method.get("createdDateTime", "N/A")
                        parsed_method["lifetimeInMinutes"] = method.get("lifetimeInMinutes", "N/A")
                        parsed_method["isUsable"]         = method.get("isUsable", "N/A")
                        parsed_method["isUsableOnce"]     = method.get("isUsableOnce", "N/A")

                    elif "x509certificateauthenticationmethod" in method_odata_type:
                        # https://learn.microsoft.com/en-us/graph/api/resources/x509certificateauthenticationmethod
                        parsed_method["methodType"]           = "x509Certificate"
                        parsed_method["certificateUserIds"]   = method.get("certificateUserIds", [])
                        parsed_method["createdDateTime"]      = method.get("createdDateTime", "N/A")
                        parsed_method["displayName"]          = method.get("displayName", "N/A")

                    elif "passwordauthenticationmethod" in method_odata_type:
                        # https://learn.microsoft.com/en-us/graph/api/resources/passwordauthenticationmethod
                        parsed_method["methodType"]       = "password"
                        parsed_method["createdDateTime"]  = method.get("createdDateTime", "N/A")

                    else:
                        # Fallback value
                        parsed_method["methodType"] = "other-or-unknown"

                    mfa_methods.append(parsed_method)

                user_details["mfaMethods"] = mfa_methods

            else:
                # no self.error() if there is permission issue
                user_details["mfaMethods"] = []
                user_details["mfaError"] = (
                    f"Failed to retrieve MFA methods (HTTP {mfa_r.status_code}). "
                    f"Details: {mfa_r.content.decode('utf-8', errors='replace')}"
                )

            self.report(user_details)

        except Exception as ex:
            self.error(traceback.format_exc())

    def handle_get_directoryAuditLogs(self, headers, base_url):
        """
        Retrieves Directory Audit logs from Microsoft Entra ID (Azure AD).
        Reference: https://learn.microsoft.com/en-us/graph/api/directoryaudit-list
        """
        if self.data_type != 'mail':
            self.error('Incorrect dataType. "mail" expected.')
        try:
            # Pull the userPrincipalName from the observable data (data_type=mail)
            self.user = self.get_data()
            if not self.user:
                self.error("No user principal name supplied for directory audit logs")
            self.guid = self.ensure_user_guid(base_url, headers)
            
            # Calculate time range (past X days)
            filter_time = datetime.utcnow() - timedelta(days=self.time_range)
            filter_time_str = filter_time.strftime('%Y-%m-%dT%H:%M:%SZ')

            # Build endpoint
            # Example: GET /auditLogs/directoryAudits?$filter=activityDateTime ge 2023-01-01T00:00:00Z&$top=12
            endpoint = (
                "auditLogs/directoryAudits?"
                f"$filter=activityDateTime ge {filter_time_str} "
                f"and initiatedBy/user/id eq '{self.guid}'"
                f"&$top={self.lookup_limit}"
            )

            # Perform the GET request
            r = requests.get(base_url + endpoint, headers=headers)
            if r.status_code != 200:
                self.error(f"Failure to fetch directory audit logs: {r.content}")

            # Parse the returned JSON
            audit_data = r.json().get('value', [])

            # Build the result object
            result = {
                "filterParameters": {
                    "timeRangeDays": self.time_range,
                    "lookupLimit": self.lookup_limit,
                    "startTime": filter_time_str
                },
                "directoryAudits": audit_data
            }

            # Return the results to TheHive
            self.report(result)

        except Exception as ex:
            self.error(traceback.format_exc())

    def handle_get_devices(self, headers, base_url):
        """
        Retrieves enrolled device(s) from Intune by either:
        - deviceName (hostname) if self.data_type == 'hostname', or
        - userPrincipalName (mail) if self.data_type == 'mail'.
        
        Reference: https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list
        """
        try:
            # Check if the data_type is valid
            if self.data_type not in ['hostname', 'mail']:
                self.error('Incorrect dataType. Expected "hostname" or "mail".')
            
            # Get the query value from the observable data
            query_value = self.get_data()
            if not query_value:
                if self.data_type == 'hostname':
                    self.error("No device name supplied")
                else:
                    self.error("No user UPN supplied")
            
            if self.data_type == 'mail':
                self.user = query_value
                # Resolve UPN to GUID and use exact match
                # guid = self.ensure_user_guid(base_url, headers)
                endpoint = (
                    f"deviceManagement/managedDevices?"
                    f"$filter=userPrincipalName eq '{self.user}'"
                )
            else:
                # Use startswith for partial hostname matches
                endpoint = (
                    f"deviceManagement/managedDevices?"
                    f"$filter=startswith(deviceName,'{query_value}')"
                )
            
            # Perform the GET request
            r = requests.get(base_url + endpoint, headers=headers)
            if r.status_code != 200:
                self.error(f"Failure to pull device(s) for query '{query_value}': {r.content}")
            
            # Parse and report the results
            devices_data = r.json().get('value', [])
            self.report({"query": query_value, "devices": devices_data})
        
        except Exception as ex:
            self.error(traceback.format_exc())

    
    def run(self):
        Analyzer.run(self)

        token = self.authenticate()
        headers = { 'Authorization': f'Bearer {token}' }
        base_url = 'https://graph.microsoft.com/v1.0/'

        # Decide which service to run
        if self.service == "getSignIns":
            self.handle_get_signins(headers, base_url)
        elif self.service == "getUserInfo":
            self.handle_get_userinfo(headers, base_url)
        elif self.service == "getDirectoryAuditLogs":
            self.handle_get_directoryAuditLogs(headers, base_url)
        elif self.service == "getManagedDevicesInfo":
            self.handle_get_devices(headers, base_url)
        else:
            self.error({"message": "Unidentified service"})

    def summary(self, raw):
        taxonomies = []
        if self.service == "getSignIns":
            if len(raw.get('signIns', [])) == 0:
                taxonomies.append(self.build_taxonomy('info', 'MSEntraIDSignins', 'SignIns', 'None'))
            else:
                taxonomies.append(self.build_taxonomy('safe', 'MSEntraIDSignins', 'Count', len(raw['signIns'])))

            stats = raw.get("sum_stats", {})
            if stats.get("riskySignIns", 0) != 0:
                taxonomies.append(self.build_taxonomy('suspicious', 'MSEntraIDSignins', 'Risky', stats["riskySignIns"]))
            if stats.get("externalStateSignIns", 0) != 0:
                taxonomies.append(self.build_taxonomy('suspicious', 'MSEntraIDSignins', 'OutOfState', stats["externalStateSignIns"]))
            if stats.get("foreignSignIns", 0) != 0:
                taxonomies.append(self.build_taxonomy('malicious', 'MSEntraIDSignins', 'ForeignSignIns', stats["foreignSignIns"]))
        
        elif self.service == "getUserInfo":
            if raw.get('userPrincipalName'):
                                taxonomies.append(
                                    self.build_taxonomy(
                                        "info",
                                        "MSEntraIDUserInfo",
                                        "UPN",
                                        raw["userPrincipalName"]
                                    )
                                )
        elif self.service == "getDirectoryAuditLogs":
            # Get the count of directory audit logs
            count = len(raw.get("directoryAudits", []))
            taxonomies.append(self.build_taxonomy('info', 'MSEntraIDAuditLogs', 'count', count))
        elif self.service == "getManagedDevicesInfo":
            # Get the count of devices returned.
            count = len(raw.get("devices", []))
            taxonomies.append(self.build_taxonomy('info', 'MSEntraIDManagedDevices', 'count', count))
        return {'taxonomies': taxonomies}

    def artifacts(self, raw):
        artifacts = []
        raw_str = str(raw)

        # Attempt to parse the raw data as JSON to later capture structured fields
        #try:
        #    data = json.loads(raw_str)
        #except Exception:
        #    data = None

        extracted_data = self.get_data()  # Store observed value
        observed_type = self.data_type    # Store expected data type

        # Extract IPv4 addresses
        ipv4_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ipv4s = re.findall(ipv4_regex, raw_str)
        for ip in set(ipv4s):
            if not (observed_type == "ip" and extracted_data == ip):
                artifacts.append(self.build_artifact('ip', ip))

        # Extract IPv6 addresses
        ipv6_regex = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        ipv6s = re.findall(ipv6_regex, raw_str)
        for ip in set(ipv6s):
            if not (observed_type == "ip" and extracted_data == ip):
                artifacts.append(self.build_artifact('ip', ip))

        # Extract email addresses
        email_regex = r'[\w\.-]+@[\w\.-]+\.\w+'
        emails = re.findall(email_regex, raw_str)
        for email in set(emails):
            if not (observed_type == "mail" and extracted_data == email):
                artifacts.append(self.build_artifact('mail', email))

        return artifacts

if __name__ == '__main__':
    MSEntraID().run()
