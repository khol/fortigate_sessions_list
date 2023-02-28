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

api_token = <API_TOKEN_TO_THE_FORTIGATE_ATLEAST_READONLY>
VDOM = <vdome>

headers = {
  "Authorization": "Bearer " + api_token
}
filename = "./csessions.txt"
#filename = "/home/<user>/fortigate_sessions_list/csessions.txt"
expiration_time = timedelta(minutes=30)
number_of_sessions = 10

exclude_list = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "1.2.3.4"]

#check if the file alredy exist
if not os.path.isfile(filename):
    open(filename, 'a').close()


while True:
  # https://docs.fortinet.com/document/fortigate/7.0.0/new-features/270209/clear-multiple-sessions-with-rest-api-7-0-2
  #url = "https://"+<hostname/ip:port>+"/api/v2/monitor/firewall/session?count=1000&destport=53&filter-csf=false&ip_version=ipboth&start=0&summary=true&vdom="+VDOM
  url = "https://"+<hostname/ip:port>+"/api/v2/monitor/firewall/session?count=10000&filter-csf=false&ip_version=ipboth&start=0&summary=true&vdom="+VDOM

  response = requests.get(url, headers=headers, verify=False)

  if response.status_code == 200:
      # Lista på alla sessions
      session_list = response.json()["results"]["details"]
      # Använd Counter från collections modulen för att räkna upp antalet förekomster av varje saddr
      saddr_counter = Counter(session['saddr'] for session in session_list)
      # Skapa en lista med bara de sessions som förekommer fler än 5 gånger
      common_sessions = [saddr for saddr, count in saddr_counter.items() if count >= number_of_sessions]
      # Skriv ut den nya listan
      #print(common_sessions)

      # Nuvarande minut
      current_time = datetime.now().replace(second=0, microsecond=0)

      # Rensa bort gamla rader från filen
      with open(filename, "r") as f:
          lines = f.readlines()
      with open(filename, "w") as f:
          timeclean = False
          for line in lines:
            try:
                timestamp = datetime.strptime(line.lstrip('#').strip(), "%Y-%m-%d %H:%M:%S")
                #print (f"current_time: {current_time} / timestamp: {timestamp} / expiration_time: {expiration_time} ")
                if current_time - timestamp < expiration_time:
                    timeclean = True
                    f.write(line)
            except ValueError:
                # Ignore lines that don't start with a timestamp
                if timeclean:
                  f.write(line)
                else:
                  timeclean = False
                #f.write(line)


      # Tidsstämpel för senaste blocket i filen
      last_block_time = None
      with open(filename, "r") as f:
        lines = f.readlines()
        if lines:
            for i, line in enumerate(lines):
                if ":" not in line:
                    continue
                try:
                    line_time = float(line.split(":")[0])
                except ValueError:
                    continue
                if time.time() - line_time < expiration_time.total_seconds():
                    lines = lines[i:]
                    break
            try:
                last_block_time = datetime.strptime(lines[0].strip("#\n"), "%Y-%m-%d %H:%M:%S")
            except ValueError:
                last_block_time = None
        else:
          lines = []

      # Skriv till filen om det är en ny minut
      if current_time != last_block_time:
        with open(filename, "a") as f:
          f.write(f"#{current_time}\n")
          #for csessions in common_sessions:
          #  f.write(f"{csessions}\n")
          for csessions in common_sessions:
            if not any(ipaddress.ip_address(csessions) in ipaddress.ip_network(exclude) for exclude in exclude_list):
              f.write(f"{csessions}\n")

      time.sleep(20) # Vänta 20 sekunder innan nästa anrop.
  else:
    if response.status_code == 403:
      print("some authentication missmatch for apia token, HTTP Code: ", response.status_code)
    else:
      print("Some Error, HTTP Code: ", response.status_code)

# Stäng
