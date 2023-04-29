import requests
# för att ta bort alla varningar för https
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#api_token = <API_TOKEN_TO_THE_FORTIGATE_ATLEAST_READONLY>

#firewwall name and token
FIREWALLSTOKEN = [ {'name': <hostname/ip>, 'token': <api_token_for_fw>},{'name': <hostname/ip>, 'token': <api_token_for_fw>}]

#Exsternal Connection block list name
BLOCK_LIST_NAME = <name of the blocklist>
#path to where to find the blocklist.
url

# loop thorugh the firewall list
for firewall in FIREWALLSTOKEN:
  #handele the api token
  headers = {
    "Authorization": "Bearer " + firewall['token']
  }
  #url for the refresh
  url = "https://"+firewall['name']+"/api/v2/monitor/system/external-resource/refresh?mkey="+BLOCK_LIST_NAME
  #respond and post
  response = requests.post(url, headers=headers, verify=False, timeout=2)
  #print status.
  print(f"{firewall['name']} response: {response}")


#  put
#name: "AUTO-DRIFTEN-BLOCK
for firewall in FIREWALLSTOKEN:  
  #handele the api token
  headers = {
    "Authorization": "Bearer " + firewall['token']
  }
  #url
  url = "https://"+firewall['name']+"/api/v2/cmdb/system/external-resource/"+BLOCK_LIST_NAME+"?datasource=1&with_meta=1"
  #payload for update, if new path to file
  payload = {'name': BLOCK_LIST_NAME, 'resource' : 'http://'+url}
  #connect and get the respondcode
  response = requests.put(url, headers=headers, json=payload, verify=False )
  print (f"{firewall['name']} response: {response}")
