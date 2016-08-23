"""
An OpenFlow 1.0  L2 stealth firewall implementation.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet, ethernet, ipv4
from netaddr import IPNetwork, IPAddress
from ryu.lib.mac import haddr_to_bin

PROTO_TCP = 6
PROTO_UDP = 17
ETH_ARP = 0x0806
ETH_IP = 0x0800

PORT_DNS = 53
PORT_WEB = 80

DMZ_RANGE = IPNetwork('10.0.3.0/24')
INET_RANGE = IPNetwork('10.0.1.0/24')
INTERNET_RANGE = IPNetwork('10.0.2.0/24')

OUT_RANGE = list(DMZ_RANGE) +  list(INTERNET_RANGE)
IN_RANGE = list(INET_RANGE)

class Firewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Firewall, self).__init__(*args, **kwargs)
        self.states = set()


    def add_flow(self, datapath, match, out_port, idle_to, hard_to):
        ofproto = datapath.ofproto

        if out_port:
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        else:
            actions = []

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=idle_to, hard_timeout=hard_to,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        #ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype != ETH_IP:
            # ignore not ip packets
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        if eth.ethertype == ETH_IP:
            ip4 = pkt.get_protocol(ipv4.ipv4)
            #ipv4(csum=4395,dst='10.0.0.2',flags=2,header_length=5,identification=5500,offset=0,option=None,proto=1,src='10.0.0.1',tos=0,total_length=84,ttl=64,version=4)
                             
            if IPAddress(ip4.src) in IN_RANGE:
                self.states.add(ip4.src, ip4.dst)
                #if the conection is allowed, it won't send anything, and the backend neither from this module. So the core finally will install 
                # a flow rule from the L2S module
                return
            elif (ip4.dst, ip4.src) in self.states:
                # there is a connection open, so 
                return
            else :
                #block connection (DROP packet)
                #add flow and packet_out with no actions
                match = datapath.ofproto_parser.OFPMatch(dl_type = ETH_IP, ipv4_src = ip4.src, ipv4_dst = ip4.dst, dl_dst=haddr_to_bin(dst), dl_src=haddr_to_bin(src))
                self.add_flow(datapath, match, None, 5, 0)
                self.forwardPacket(msg, None)


    def forwardPacket(self, msg, outPort):
        # Does not install a rule. Just forwards this packet.
        datapath=msg.datapath

        ofproto = datapath.ofproto

        data=None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        if msg.buffer_id is not ofproto.OFP_NO_BUFFER:
            if not outPort:
                po_actions =[] #no actions = drop
            else:
                po_actions = [datapath.ofproto_parser.OFPActionOutput(outPort)]

            pkt_out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port, data=data, actions=po_actions)
            datapath.send_msg(pkt_out)



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


    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        try:
            self.states.remove((msg.match['ipv4_src'], msg.match['ipv4_dst']))
        except:
            self.logger.exception('remove state ERROR')
            pass
