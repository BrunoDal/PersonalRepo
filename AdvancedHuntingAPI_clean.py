import json
from unicodedata import name
import urllib.request
import urllib.parse

class M365API :
    accesstoken = ""
    def init(self):
        #Connect to tenant
        tenantId = '' # Le tenant ID
        appId = '' # L'app ID
        appSecret = '' # Le secret lié à l'app

        url = "https://login.microsoftonline.com/%s/oauth2/token" % (tenantId)

        resourceAppIdUri = 'https://api.security.microsoft.com' # important de s'authentifier ici et non pas sur api.securitycenter.microsoft.com !

        body = {
            'resource' : resourceAppIdUri,
            'client_id' : appId,
            'client_secret' : appSecret,
            'grant_type' : 'client_credentials'
        }

        data = urllib.parse.urlencode(body).encode("utf-8")

        req = urllib.request.Request(url, data)
        response = urllib.request.urlopen(req)
        jsonResponse = json.loads(response.read())
        self.accesstoken = jsonResponse["access_token"]
    
    

    def RequestAH(self,query):
        url = "https://api.security.microsoft.com/api/advancedhunting/run" #l'endpoint de l'API
        headers = { 
            'Content-Type' : 'application/json',
            'Accept' : 'application/json',
            'Authorization' : "Bearer " + self.accesstoken
        }

        data = json.dumps({ 'Query' : query }).encode("utf-8")
        
        req = urllib.request.Request(url, data, headers=headers)
        response = urllib.request.urlopen(req)

        jsonResponse = json.loads(response.read())
        return jsonResponse

requester = M365API()
requester.init() #on se connecte et on récupère le token
requestAH = "EmailEvents | where ThreatTypes contains 'phish' | join EmailUrlInfo on NetworkMessageId | project Url" #la requête advanced hunting en question

responseAH = requester.RequestAH(requestAH)

print(responseAH["Results"]) #on affiche juste les résultats
