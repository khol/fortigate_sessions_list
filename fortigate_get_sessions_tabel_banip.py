#!/usr/bin/env python
import requests
from collections import Counter
from datetime import datetime, timedelta
from datetime import datetime
import numpy as np
import time
import os
import re
import ipaddress
import json

# för att ta bort alla varningar för https
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#https://github.com/fortinet-solutions-cse/fortiosapi/blob/master/fortiosapi/fortiosapi.py
#https://www.used.net.ua/index.php/fajlovyj-arkhiv/category/35-fortinet.html?download=83:fortios-5-6-11-rest-api-reference
# https://docs.fortinet.com/document/fortigate/7.0.0/new-features/270209/clear-multiple-sessions-with-rest-api-7-0-2


#api_token = <API_TOKEN_TO_THE_FORTIGATE_ATLEAST_READONLY>
#VDOM = <vdome>
#"VDOM = "root"

#where the firewall information and token and vdom information is 
with open('firewall_inventory.json', 'r') as f:
  FIREWALLSTOKEN = json.load(f)


#how many sessions should be allowd before block
number_of_sessions = 200
#how long time should the block be active
ban_timer_sec = 1800
#exclude list is what ips should not be blocked
exclude_list = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]
exclude_list = ["10.0.0.0/8", "172.16.0.0/12"]



headers = {
  "Authorization": "Bearer " + FIREWALLSTOKEN['token']
}



# Get the current date and time
now = datetime.now()
# Format the date and time string
formatted_date = now.strftime("%Y-%m-%d %H:%M:%S")

#print what have been put to Qurantine Monitor
def get_qurantine(FIREWALLSTOKEN):
  url = f"https://{FIREWALLSTOKEN['name']}/api/v2/monitor/user/banned/select/?vdom={FIREWALLSTOKEN['vdom']}"
  response = requests.get(url, headers=headers, verify=False)
  if response.status_code == 200:
    session_list = response.json()["results"]
    #print (f'session_list: {session_list}')
    for i in session_list:
      print (f"expires: {datetime.fromtimestamp(i['expires'])} created: {datetime.fromtimestamp(i['created'])} ip_address: {i['ip_address']} source: {i['source']} ipv6: {i['ipv6']}")

def print_to_file_3_4(saddr_counter):
  with open('sessions_3_4_delar_av_max.txt', 'a') as file:
    # write a string to the file
    start = '*'*20+f'{formatted_date}'+'*'*20+f'\n'
    file.write( start )
    for key, value in saddr_counter.items():
      if value > ((number_of_sessions/4)*3):
        #print (f"if_saddr_counter: {value} - {key}")
        file.write(f'{key}: {value}'+f'\n')
    file.write('*'*30+f'\n')

def print_to_file_banip_list(ban_list):
  with open('session_banip_list.txt', 'a') as file:
    # write a string to the file
    start = '*'*20+f'{formatted_date}'+'*'*20+f'\n'
    file.write( start )
    for ban_ip in ban_list:
      #print (f"if_saddr_counter: {value} - {key}")
      file.write(f'{ban_ip}'+f'\n')
    file.write('*'*30+f'\n')

while True:
  ban_list = []
  url = f"https://{FIREWALLSTOKEN['name']}/api/v2/monitor/firewall/session?count=10000&filter-csf=false&ip_version=ipboth&start=0&summary=true&vdom={FIREWALLSTOKEN['vdom']}"

  response = requests.get(url, headers=headers, verify=False)

  if response.status_code == 200:
      # Lista på alla sessions
      session_list = response.json()["results"]["details"]
      # Använd Counter från collections modulen för att räkna upp antalet förekomster av varje saddr
      saddr_counter = Counter(session['saddr'] for session in session_list)

      #print to file, for all 3/4 of max
      print_to_file_3_4(saddr_counter)
      
      # Skapa en lista med bara de sessions som förekommer fler än 5 gånger
      common_sessions = [saddr for saddr, count in saddr_counter.items() if count >= number_of_sessions]
      # Skriv ut den nya listan

      for csessions in common_sessions:
        if not any(ipaddress.ip_address(csessions) in ipaddress.ip_network(exclude) for exclude in exclude_list):
          ban_list.append (csessions)

      #post 
      #if there is multiple firewalls to block ips in, do this to a forloop, and comment out FIREWALLSTOKEN and uncomment firewall
    #  for firewall in FIREWALLSTOKEN:
        firewall_name = FIREWALLSTOKEN['name']
        firewall_token = FIREWALLSTOKEN['token']
        firewall_vdom = FIREWALLSTOKEN['vdom']
    #    firewall_name = firewall['name']
    #    firewall_token = firewall['token']
    #    firewall_vdom = firewall['vdom']
      #handele the api token
      headers = {
        "Authorization": "Bearer " + firewall_token
      }
      #url
      url = f"https://{firewall_name}/api/v2/monitor/user/banned/add_users/?vdom={firewall_vdom}"

      #payload for update, if new path to file
      payload = {'ip_addresses': ban_list,"expiry": ban_timer_sec}

      #connect and get the respondcode
      response = requests.post(url, headers=headers, json=payload, verify=False )

      #print all ban ip to file
      print_to_file_banip_list(ban_list)

      arr = np.array(ban_list)
      print(f'ban ip list count: {arr.size}')
      time.sleep(5) # Vänta 20 sekunder innan nästa anrop.
      
      #print all ips from the Quarantine Monitor
      get_qurantine(FIREWALLSTOKEN)
      

  else:
    if response.status_code == 403:
      print("some authentication missmatch for apia token, HTTP Code: ", response.status_code)
    elif response.status_code == 405:
      print("Method Not Allowed response status code indicates that the server knows the request method, HTTP Code: ", response.status_code)
    else:
      print("Some Error, HTTP Code: ", response.status_code)



# Stäng