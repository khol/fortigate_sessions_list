import requests
# för att ta bort alla varningar för https
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#api_token = <API_TOKEN_TO_THE_FORTIGATE_ATLEAST_READONLY>

#firewwall name and token
FIREWALLSTOKEN = [ {'name': <hostname/ip>, 'token': <api_token_for_fw>},{'name': <hostname/ip>, 'token': <api_token_for_fw>}]

# loop thorugh the firewall list
for firewall in FIREWALLSTOKEN:
  #handele the api token
  headers = {
    "Authorization": "Bearer " + firewall['token']
  }
  #url for the refresh
  url = "https://"+firewall['name']+"/api/v2/monitor/system/external-resource/refresh?mkey=AUTO-DRIFTEN-BLOCK"
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
  url = "https://"+firewall['name']+"/api/v2/cmdb/system/external-resource/AUTO-DRIFTEN-BLOCK?datasource=1&with_meta=1"
  #payload for update, if new path to file
  payload = {'name': "AUTO-DRIFTEN-BLOCK", 'resource' : 'http://blocklist-service.ops.aza.nu/blocklists/onlyfortests'}
  #connect and get the respondcode
  response = requests.put(url, headers=headers, json=payload, verify=False )
  print (f"{firewall['name']} response: {response}")
