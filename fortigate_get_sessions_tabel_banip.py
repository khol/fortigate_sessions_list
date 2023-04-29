import requests
from collections import Counter
from datetime import datetime, timedelta
import time
import os
import re
import ipaddress
# för att ta bort alla varningar för https
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#https://github.com/fortinet-solutions-cse/fortiosapi/blob/master/fortiosapi/fortiosapi.py
#https://www.used.net.ua/index.php/fajlovyj-arkhiv/category/35-fortinet.html?download=83:fortios-5-6-11-rest-api-reference
# https://docs.fortinet.com/document/fortigate/7.0.0/new-features/270209/clear-multiple-sessions-with-rest-api-7-0-2


#api_token = <API_TOKEN_TO_THE_FORTIGATE_ATLEAST_READONLY>
#VDOM = <vdome>
#"VDOM = "root"

number_of_sessions = 5
ban_timer_sec = 1800
exclude_list = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]



headers = {
  "Authorization": "Bearer " + api_token
}

ban_list = []

#print what have been put to Qurantine Monitor
def get_qurantine(FIREWALLSTOKEN):
  url = f"https://{FIREWALLSTOKEN[0]['name']}/api/v2/monitor/user/banned/select/?vdom={FIREWALLSTOKEN[0]['vdom']}}"
  response = requests.get(url, headers=headers, verify=False)
  if response.status_code == 200:
    session_list = response.json()["results"]
    #print (f'session_list: {session_list}')
    for i in session_list:
      print (f"expires: {datetime.fromtimestamp(i['expires'])} created: {datetime.fromtimestamp(i['created'])} ip_address: {i['ip_address']} source: {i['source']} ipv6: {i['ipv6']}")


while True:
  url = f"https://{FIREWALLSTOKEN[0]['name']}/api/v2/monitor/firewall/session?count=10000&filter-csf=false&ip_version=ipboth&start=0&summary=true&vdom={FIREWALLSTOKEN[0]['vdom']}"

  response = requests.get(url, headers=headers, verify=False)

  if response.status_code == 200:
      # Lista på alla sessions
      session_list = response.json()["results"]["details"]
      # Använd Counter från collections modulen för att räkna upp antalet förekomster av varje saddr
      saddr_counter = Counter(session['saddr'] for session in session_list)
      # Skapa en lista med bara de sessions som förekommer fler än 5 gånger
      common_sessions = [saddr for saddr, count in saddr_counter.items() if count >= number_of_sessions]
      # Skriv ut den nya listan

      for csessions in common_sessions:
        if not any(ipaddress.ip_address(csessions) in ipaddress.ip_network(exclude) for exclude in exclude_list):
          ban_list.append (csessions)

      #  post
      for firewall in FIREWALLSTOKEN:  
        #handele the api token
        headers = {
          "Authorization": "Bearer " + firewall['token']
        }

        #url
        url = f"https://{firewall['name']}/api/v2/monitor/user/banned/add_users/?vdom={firewall['vdom']}"

        #payload for update, if new path to file
        payload = {'ip_addresses': ban_list,"expiry": ban_timer_sec}

        #connect and get the respondcode
        response = requests.post(url, headers=headers, json=payload, verify=False )


      time.sleep(5) # Vänta 20 sekunder innan nästa anrop.
      
      get_qurantine(FIREWALLSTOKEN)
      

  else:
    if response.status_code == 403:
      print("some authentication missmatch for apia token, HTTP Code: ", response.status_code)
    elif response.status_code == 405:
      print("Method Not Allowed response status code indicates that the server knows the request method, HTTP Code: ", response.status_code)
    else:
      print("Some Error, HTTP Code: ", response.status_code)



# Stäng