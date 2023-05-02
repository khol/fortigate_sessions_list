# fortigate_sessions_list



crontab -e  
*/5 * * * * /bin/bash /home/< user>/fortigate_sessions_list/start_script.sh

check if the script is running, path. 
  /home/< user>/fortigate_sessions_list/start_script.sh

the script that is running is geting 1000 sessions each 20s, and put them in the script.  
  fortigate_get_sessions_tabel.py

to link a txt file from a web server, to the original file. 
  sudo ln -s /home/< user>/fortigate_sessions_list/csessions.txt /var/www/html/csessions.txt

change:  
  < api_token> - add the correct api token, as a string.\
  < ip address:port> - in the fortigate_get_sessions_tabel.py script.\
  < user> - change all user parameters to correkt user, if the path is okay. \
  you might need to add a empty txt file\

# fortigate_get_sessions_tabel_banip
the script is to ban ips, that has more active sessions than somthing.

## files to change 
fortigate_get_sessions_tabel_banip.py
example_firewall_inventory.json

## value to change 
### how many conncurent sessions should trigger a ban
number_of_sessions = 200 
### how long time should the ip be band
ban_timer_sec = 1800
### any ip address or cidr that should be excluded
exclude_list = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]

### change below to the fortigate to check and send to
 {"name": "s.x.y.z", "token": "token_password", "vodm": "vdom" }