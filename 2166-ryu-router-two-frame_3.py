#Dionisis Basdanis 2166

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

"""
Two OpenFlow 1.0 L3 Static Routers and two OpenFlow 1.0 L2 learning switches.
"""




from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ofproto_v1_5
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.ofproto import ether
from ryu.ofproto import inet

VLAN_BLUE_MAC = "00:00:00:00:01"
VLAN_ORANGE_MAC = "00:00:00:02"
LEFT_NET_IP = "192.168.1.1"
RIGHT_NET_IP = "192.168.2.1"
LEFT_NET_MAC = "00:00:00:00:01:01"
RIGHT_NET_MAC = "00:00:00:00:02:01"
LEFT_ROUTER_MAC = "00:00:00:00:03:01"
RIGHT_ROUTER_MAC = "00:00:00:00:03:02"
BROADCAST = "ff:ff:ff:ff:ff:ff"
IPV4 = 0x0800

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dpid == 0x1A:
            if eth.ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                arpPacket = pkt.get_protocol(arp.arp)
		if arpPacket.opcode == 1 and arpPacket.dst_ip == LEFT_NET_IP:
			dstIp = arpPacket.src_ip
			dstMac = src
			srcMac = LEFT_NET_MAC
			srcIp =  arpPacket.dst_ip
			outPort = msg.in_port
			self.send_arp_reply(datapath,srcMac,srcIp,dstMac,dstIp,outPort)
			return
            elif eth.ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
			pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
			if pkt_ipv4 :
				srcIp = pkt_ipv4.src
				dstIp = pkt_ipv4.dst
				port = msg.in_port
				if dstIp[:9] in LEFT_NET_IP and port == 1:
					srcMac = LEFT_NET_MAC
                    			dstMac = BROADCAST
                   			outPort = 2
                               '''
                   			************************
                    			match = datapath.ofproto_parser.OFPMatch(dl_type = IPV4,nw_dst_mask = 24,nw_dst = LEFT_NET_IP,in_port=1)
                            ************************
                            '''
                    			actions = [datapath.ofproto_parser.OFPActionSetDlSrc(srcMac),datapath.ofproto_parser.OFPActionSetDlDst(dstMac),datapath.ofproto_parser.OFPActionOutput(outPort)]
                        		self.add_flow(datapath,match,actions)
				elif dstIp[:9] in RIGHT_NET_IP and port == 2:
					srcMac = LEFT_ROUTER_MAC
                                        dstMac = RIGHT_ROUTER_MAC 
                                        outPort = 1
                                        match = datapath.ofproto_parser.OFPMatch(dl_type = IPV4,in_port=2)
                                        actions = [datapath.ofproto_parser.OFPActionSetDlSrc(srcMac),datapath.ofproto_parser.OFPActionSetDlDst(dstMac),datapath.ofproto_parser.OFPActionOutput(outPort)]
                                        self.add_flow(datapath,match,actions)
			'''
			********************
			 out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,buffer_id=0xffffffff,in_port=msg.in_port,actions=actions,data=p.data)
             datapath.send_msg(out)
			****************
            '''
		                return
            		return
        if dpid == 0x1B:
            if eth.ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                arpPacket = pkt.get_protocol(arp.arp)
		if arpPacket.opcode == 1 and arpPacket.dst_ip == RIGHT_NET_IP:
                        dstIp = arpPacket.src_ip
                        dstMac = src
                        srcMac = RIGHT_NET_MAC
                        srcIp = arpPacket.dst_ip
                        outPort = msg.in_port
                        self.send_arp_reply(datapath,srcMac,srcIp,dstMac,dstIp,outPort)
                	return
            elif eth.ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
                        if pkt_ipv4:
                                srcIp = pkt_ipv4.src
                                dstIp = pkt_ipv4.dst
                                port = msg.in_port
                                if dstIp[:9] in LEFT_NET_IP and port == 2: 
                                        srcMac = RIGHT_ROUTER_MAC
                                        dstMac = LEFT_ROUTER_MAC
                                        outPort = 1
                                        match = datapath.ofproto_parser.OFPMatch(dl_type = IPV4,in_port=2)
                                        actions = [datapath.ofproto_parser.OFPActionSetDlSrc(srcMac),datapath.ofproto_parser.OFPActionSetDlDst(dstMac),datapath.ofproto_parser.OFPActionOutput(outPort)]
                                        self.add_flow(datapath,match,actions)
				elif dstIp[:9] in RIGHT_NET_IP and port == 1:
                            #           srcMac = RIGHT_NET_MAC
                                        dstMac = BROADCAST
                                        outPort = 2
                                        match = datapath.ofproto_parser.OFPMatch(dl_type = IPV4,in_port=1)
                                        actions = [datapath.ofproto_parser.OFPActionSetDlSrc(srcMac),datapath.ofproto_parser.OFPActionSetDlDst(dstMac),datapath.ofproto_parser.OFPActionOutput(outPort)]
                                        self.add_flow(datapath,match,actions)
                '''
                ************************
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,buffer_id=0xffffffff,in_port=msg.in_port,actions=actions,data=p.data)
                datapath.send_msg(out)
                ************************
                '''
                		return
            		return

	#trunk link 8a prepei na koitaw to vlan tag gia na dw apo poio vlan xrhsimopoieitai
	#apo to h1 sto h4, anoikoun sto idio vlan
	#prepei na to steilw mesw tou trunk link
	#enw apo to h1 sto h2, anoikoun se diaforetiko vlan
	#prepei na to steilw mesw tou router
	#PROSOXH na kanw return sto telos
	#gia na steilei to switch to kanw opws me ton router me thn add_flow

	if dpid == 0x2:	#left switch

		if dstMac[:14] in VLAN_BLUE_MAC and port == 3: #an to paketo stelnetai apo ton h1 kai paei ston h4
			srcMac = 
			dstMac =
			outPort = 
			match = dataparh.ofproto_parser.OFPMatch				
			 
		elif dstMac[:14] in VLAN_ORANGE_MAC and port == 3: #apo ton h1 ston h2 'h h3 prepei na paei mesw tou router
	
		elif dstMac[:14] in VLAN_BLUE_MAC and port == 4: #apo ton h4 ston h1 'h h4
		
		elif dstMac[:14] in VLAN_ORANGE_MAC and port ==4: #an to paketo stelnetai apo ton 

	if dpid == 0x3: #right switch

		if dstMac[:14] in VLAN_BLUE_MAC and port == 3: #apo ton h3 ston h4 'h h1 mesw router

		elif dstMac[:14] in VLAN_ORANGE_MAC and port == 3: #apo ton h3 ston h2

		elif dstMac[:14] in VLAN_BLUE_MAC and port == 4: #apo ton h4 ston h1

		elif dstMac[:14] in VLAN_ORANGE_MAC and port == 4: #apo ton h4 ston h2 'h h3 mesw router

                 
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        match = datapath.ofproto_parser.OFPMatch(
            in_port=msg.in_port, dl_dst=haddr_to_bin(dst))

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    #kanei to packet out gia to switch

#    def send_packet_switch(self, datapath, port, pkt):
#	ofproto = datapath.ofproto
#	parser = datapath.ofproto_parser
#	pkt_serialize()
#	self.logger.info("packet-out %s" % (pkt,))
#	data = pkt.data
#	actions = [parser.OFPActionOutput(port = port)]
#	out = parse.OFPPacketOut(datapath=datapath,
#				 buffer_id=ofproto.OFP_NO_BUFFER,
#				 in_port=ofproto.OFPP_CONTROLLER,
#				 actions=actions,
#				 data=data)
#	datapath.send_msg(out)

    def send_arp_reply(self, datapath, srcMac, srcIp, dstMac, dstIp, outPort):
        e = ethernet.ethernet(dstMac, srcMac, ether_types.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, 2, srcMac, srcIp, dstMac, dstIp)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
