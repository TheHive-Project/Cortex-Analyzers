import requests
import urllib.request
import urllib.parse
import json
import datetime

msdefenderAppId = "a3a1267e-08f0-4417-9d34-a0ac9636f6ea"
msdefenderTenantId = "f7bab6a1-af76-41a2-a72e-0a9253b9ed40"
msdefenderSecret = "n.hv7Tiax_9Z3tFv6rUtb-D.4K7yE2p-ja"
msdefenderOAuthUr = 'https://login.windows.net/'

msdefenderSession = requests.Session()
msdefenderSession.headers.update(
    { 
	'Content-Type' : 'application/json' 
    }
)

def getToken():
    msdefenderAppId = "a3a1267e-08f0-4417-9d34-a0ac9636f6ea"
    msdefenderTenantId = "f7bab6a1-af76-41a2-a72e-0a9253b9ed40"
    msdefenderSecret = "n.hv7Tiax_9Z3tFv6rUtb-D.4K7yE2p-ja"
    msdefenderOAuthUri = 'https://login.windows.net/'
    msdefenderGrant = "client_credentials"
    msdefenderResourceAppIdUri = 'https://api.securitycenter.windows.com'
    url = "{}/{}/oauth2/token".format(
	msdefenderOAuthUri,msdefenderTenantId
	)

    body = {'grant_type':msdefenderGrant, 'resource':msdefenderResourceAppIdUri, 'client_id':msdefenderAppId, 'client_secret':msdefenderSecret}

    data = urllib.parse.urlencode(body).encode("utf-8")

    req = urllib.request.Request(url, data)
    response = urllib.request.urlopen(req)
    jsonResponse = json.loads(response.read())
    token = jsonResponse["access_token"]
    #print(json.dumps(body))
    #body = str(json.dumps(body))

    #try:
    #  req = msdefenderSession.post(url=url, json=body) 
    #except requests.exceptions.RequestException as e:
    #  print(e)

    #print(req.json)
    #jsonResponse = req.json()
    #token = req.json()
    #token = jsonResponse["access_token"]
    #url="https://httpbin.org/post"
    #token_r = requests.post(url, json={'grant_type':" client_credentials", 'resource': msdefenderResourceAppIdUri, 'client_id': msdefenderAppId, 'client_secret': msdefenderSecret})
    #print(token_r.content)

    return token

def getMachineId(session,id,observable_type):
    time = datetime.datetime.now() - datetime.timedelta(minutes=120)
    time = time.strftime("%Y-%m-%dT%H:%M:%SZ")

    if observable_type == "ip":
        url = "https://api.securitycenter.windows.com/api/machines/findbyip(ip='{}',timestamp={})".format(id,time)
    else:
        url = "https://api.securitycenter.windows.com/api/machines?$filter=computerDnsName+eq+'{}'".format(id)    

    try:
      response = session.get(url=url)
      if response.status_code == 200:
        jsonResponse = response.json()
        if len(response.content) > 100:
            return jsonResponse["value"][0]["aadDeviceId"]
        else:
            return "ERROR"
    except requests.exceptions.RequestException as e:
      print("Exception: {}".format(e))

def runFullVirusScan(machineId,session):
    url = 'https://api.securitycenter.windows.com/api/machines/{}/runAntiVirusScan'.format(machineId)

    body = {
        'Comment': 'Full scan to machine due to TheHive case {}'.format("1234"),
        'ScanType': 'Full'
       }

    try:
        response = session.post(url=url, json=body)
        if response.status_code == 201:
            print("message: Started full VirusScan on machine: {}".format(machine))
    except requests.exceptions.RequestException as e:
        print("Error")

#########
#########
token = getToken()
#print(token)

msdefenderSession.headers.update(
    {
	'Accept' : 'application/json',
	'Content-Type' : 'application/json',
        'Authorization' : 'Bearer {0}'.format(token)
    }
)

print("IP: " + getMachineId(msdefenderSession,"192.168.210.1","ip"))
print("HOST: " + getMachineId(msdefenderSession,"laptop-6gjkth4p","hostname"))

#runFullVirusScan(machine,msdefenderSession)
