# Author: Xu Han
# date: 2015.05.13
# Email: xskingdom@icloud.com
'''
This module can detect the http's request from host to Malicious URLs,
and redirect the request to decoy host. 

'''
from ryu.base import app_manager
from ryu.controller import event
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER,HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.ofproto import ether
from ryu.ofproto import inet
import time
from ryu import utils
from collections import defaultdict

ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__
IP = ipv4.ipv4.__name__
TCP = tcp.tcp.__name__

class EventURLsReqRecord(event.EventBase):
    def __init__(self,URLs):
        super(EventURLsReqRecord,self).__init__()
        self.URLs = URLs
        
class MalURLsCtrl(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _EVENTS = [EventURLsReqRecord]
    
    def __init__(self, *args, **kwargs):
        super(MalURLsCtrl, self).__init__(*args, **kwargs)
        self.mac_to_port = defaultdict(lambda:defaultdict(lambda:None))
#         self.registed_policy = defaultdict(lambda:[])
#         self.registed_protocols = []
        self.decoyHost = {"10.0.0.2":"00:00:00:00:00:02"}
        self.datapaths = {}
        self.translate_state = {}
        self.MaliciousURLs = ['10.0.0.3','10.0.0.5']
        self.URLs = []
    
    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        self.logger.info('OFPBarrierReply')
    
    def send_barrier_request(self, datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPBarrierRequest(datapath)
        datapath.send_msg(req)
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self.logger.info("switch = %d", dpid)
        self.mac_to_port.setdefault(dpid, {})
        if datapath.id not in self.datapaths:
            self.datapaths[datapath.id] = datapath
            
        '''========Clear all flow table======='''
        self.logger.info("Clearing all flow table on switch = %d ", dpid)
 
        match = parser.OFPMatch()
        inst = []
        mod = parser.OFPFlowMod(datapath=datapath, table_id=ofproto.OFPTT_ALL,
                                 command=ofproto.OFPFC_DELETE,
                                 out_port=ofproto.OFPP_ANY,
                                 out_group=ofproto.OFPP_ANY,
                                 match=match,
                                 instructions=inst)
        datapath.send_msg(mod)

        '''========Set flow entry to controller======== '''
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions,0)
   
        self.add_flow(datapath, 0, match, actions,1) #set table for tcp
       
        match_tcp = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,ip_proto=inet.IPPROTO_TCP)
        inst = [parser.OFPInstructionGotoTable(1, ofproto.OFPIT_GOTO_TABLE)]
        mod = parser.OFPFlowMod(datapath=datapath,table_id=0,priority=2,
                                match=match_tcp, instructions=inst)
        datapath.send_msg(mod)  

    def add_flow(self, datapath, priority, match, actions, table_id,buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        table_id = table_id

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,table_id=table_id,
                                    buffer_id=buffer_id,priority=priority, 
                                    match=match,instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id,
                                    priority=priority, match=match, 
                                    instructions=inst)
        datapath.send_msg(mod) 

    def packet_out(self,datapath,msg,in_port,actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = actions
        in_port = in_port

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                              in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)                   

    def handle_tcp(self,pkt,header_list,msg,datapath,parser,ofproto):
#         print "in"
        ip_pkt = header_list[IP]
        tcp_pkt = header_list[TCP]
        eth = header_list[ETHERNET]
        src_mac = eth.src
        dst_mac = eth.dst
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        src_port = tcp_pkt.src_port
        dst_port = tcp_pkt.dst_port
        decoy_ip = self.decoyHost.keys()[0]
        decoy_mac = self.decoyHost.values()[0]
      
        in_port = msg.match['in_port']
        
#         print src_ip,' to ',dst_ip," : ",src_port,' ',dst_port

        if src_ip != decoy_ip and dst_ip in self.MaliciousURLs:
            if {src_ip:dst_ip} not in self.URLs:
                self.URLs.append({src_ip:dst_ip})   
                print self.URLs                          
                self.send_event_to_observers(EventURLsReqRecord(self.URLs))
                print 'send' 
            source = (src_ip,src_mac,src_port)#, flag_mac)
            destanation = [dst_ip, dst_mac,dst_port]#, src_mac]#,dst_port]
            self.translate_state[source] = destanation
#             print self.translate_state

            if decoy_mac in self.mac_to_port[datapath.id]:
                out_port = self.mac_to_port[datapath.id][decoy_mac]
            else:
                out_port = ofproto.OFPP_FLOOD
#             print self.mac_to_port      
            actions = []
            actions.append(parser.OFPActionSetField(eth_dst=decoy_mac))
            actions.append(parser.OFPActionSetField(ipv4_dst=decoy_ip))
            actions.append(parser.OFPActionOutput(out_port))
            self.packet_out(datapath,msg,in_port,actions)            
        elif src_ip == decoy_ip:
            if dst_ip not in self.MaliciousURLs:
                if tcp_pkt.bits == 24:
                    return
                temp = (dst_ip, dst_mac, dst_port)
#                 print temp
#                 print self.translate_state
                ip = self.translate_state[temp][0]
                mac = self.translate_state[temp][1]
                #eth.dst = self.translate_state[temp][2]
                
                if eth.dst in self.mac_to_port[datapath.id]:
                    out_port = self.mac_to_port[datapath.id][dst_mac]
                else:
                    out_port = ofproto.OFPP_FLOOD
                
                actions = []
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                actions.append(parser.OFPActionSetField(eth_src=mac))
                actions.append(parser.OFPActionSetField(ipv4_src=ip))
                actions.append(parser.OFPActionOutput(out_port))                
                self.packet_out(datapath,msg,in_port,actions)  
            else:
                if eth.dst in self.mac_to_port[datapath.id]:
                    out_port = self.mac_to_port[datapath.id][eth.dst]
                else:
                    out_port = ofproto.OFPP_FLOOD
                actions = []
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                actions.append(parser.OFPActionOutput(out_port))
                self.packet_out(datapath,msg,in_port,actions)  
        elif src_ip in self.MaliciousURLs and dst_mac == decoy_mac:
            if decoy_mac in self.mac_to_port[datapath.id]:
                out_port = self.mac_to_port[datapath.id][decoy_mac]
            else:
                out_port = ofproto.OFPP_FLOOD
            actions = []
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            actions.append(parser.OFPActionOutput(out_port))
            self.packet_out(datapath,msg,in_port,actions)  
        else:
            if dst_mac in self.mac_to_port[datapath.id]:
                out_port = self.mac_to_port[datapath.id][dst_mac]
            else:
                out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]
            
            for mac in self.mac_to_port[datapath.id]:
                self.logger.info("INFO1:MAC_port_Table MAC=%s  Port=%s",mac,self.mac_to_port[datapath.id][mac])

            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, 1,msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions,1)

            self.packet_out(datapath,msg,in_port,actions)
            
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        '''*****************************PacketIn message Parser****************'''
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']       
        pkt = packet.Packet(msg.data)
        
        header_list = dict(
            (p.protocol_name, p)for p in pkt.protocols if type(p) != str)
        '''***************************Learn MAC addresses*************************'''
        eth = header_list[ETHERNET]
        src = eth.src
        dst = eth.dst
        dpid = datapath.id
        self.logger.info("INFO1: src_mac= %s dst_mac= %s ether_type=0x%02x inport= %s",src, dst, eth.ethertype, in_port)
        #self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        
        '''**************************Handle TCP***************************'''   
        if TCP in header_list:
            self.handle_tcp(pkt,header_list,msg,datapath,parser,ofproto)
            return
        '''**************************Lookup MAC table: Prepare for forwarding***************************'''
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions,0, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions,0)   
                    
        '''-----Send PacketOut Message-----'''
        self.packet_out(datapath,msg,in_port,actions)

#app_manager.require_app('ryu.app.MaliciousURLsControl.ws_URLs')
            