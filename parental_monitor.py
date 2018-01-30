# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.packet import udp

import binascii

import ConfigParser
import os
import time
import datetime

import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText


child_mac= []
blocklist = []
email = []


class SimpleSwitchPC13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchPC13, self).__init__(*args, **kwargs)

	print ("<!DOCTYPE html>")
	print ("<html>")
	print ("<head>")
	print ("<title>Zodiac Logs</title>")
	print ("</head>")
	print ("<body>")
	print ("<h1>Zodiac Logs</h1>")
	print ("")


        self.mac_to_port = {}
	
	config = ConfigParser.ConfigParser ()
	config.read ("conf.ini")
	
	temp = config.get('Configuration','email')
	emails = temp.split(',')
	for x in emails:
		email.append(x)

	
	temp = config.get('Configuration','child_mac')
	macs = temp.split(',')
	for mac in macs:
		child_mac.append(mac)

	
	temp = config.get('Configuration','blocklist')
	sites = temp.split(',')
	for site in sites:
		blocklist.append(site)

 
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

	match = parser.OFPMatch(udp_dst=53)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_MAX)]
        self.add_flow(datapath, 2, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

	
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
#        if ev.msg.msg_len < ev.msg.total_len:
 #           self.logger.debug("packet truncated: only %s of %s bytes",
  #                            ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

		
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

	udppkt = pkt.get_protocol(udp.udp)
	if udppkt != None and udppkt.dst_port ==53:
		time = datetime.datetime.now().strftime("%A, %d. %B %Y %I:%M%p")
		final_arr=  msg.data[14+20+8+13:msg.total_len-5]
		#check if the mac is matching to any of risks
		for x in child_mac:
			if x == src:
				for y in blocklist:
					if final_arr.find(y) >= 0:
						fromaddr = 'sdnhackathon1@gmail.com'
						username = 'sdnhackathon1'
						passwd = 'hackathon1'

						email_msg = MIMEMultipart()
						email_msg['From'] = fromaddr 
						email_msg['Subject'] = 'ZODIAC ADMIN : Blacklist ALERT ' + x
						message = time + ": Blocked " + x + " from " + y
						email_msg.attach(MIMEText(message))

						server = smtplib.SMTP('smtp.gmail.com:587')
						server.ehlo()
						server.starttls()
						server.ehlo()
						server.login(username,passwd)
						for z in email:
							email_msg['To'] = z 
							server.sendmail(fromaddr,z,email_msg.as_string())
						server.quit()
						print "<font size=\"3\" color=\"red\"> " + message + "</font><br>"
						return
						
		for x in blocklist:
			if final_arr.find(x) >= 0:
				print time + " user mac: " + src + " browsed blocklisted url " + blocklist + "<br>" 

		print time + " user mac: " + src + " browsed " + final_arr + "<br>" 
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

#        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
