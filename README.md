# fortigate_sessions_list



crontab -e
*/5 * * * * /bin/bash /home/<user>/fortigate_sessions_list/start_script.sh

check if the script is running, path
/home/<user>/fortigate_sessions_list/start_script.sh

the script that is running is geting 1000 sessions each 20s, and put them in the script.
fortigate_get_sessions_tabel.py

to link a txt file from a web server, to the original file
sudo ln -s /home/<user>/fortigate_sessions_list/csessions.txt /var/www/html/csessions.txt

change:  
  <api_token> - add the correct api token, as a string.  
  <ip address:port> - in the fortigate_get_sessions_tabel.py script. 
  <user> - change all user parameters to correkt user, if the path is okay. 
  you might need to add a empty txt file
