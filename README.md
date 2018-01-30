SDN Hackathon

Objective is to do a parental monitoring app using RYU controller and Zodiac OpenFlow switch.

1. Command to execute the parent control app

	ryu-manager --verbose /usr/local/lib/python2.7/dist-packages/ryu/app/parental_monitor.py > /var/www/html/logs.html 

2. Install apache web browser to monitor logs browse http://controller-ip-address/logs.html

3. Config file "conf.ini" should be placed in current directory from where you want to execute the application.
