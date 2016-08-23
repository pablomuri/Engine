"""
An OpenFlow 1.0  L2 learning switch/firewall_1 implementation.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4
from ryu.lib.packet import ether_types
from netaddr import IPAddress, IPNetwork


PROTO_TCP = 6
PROTO_UDP = 17
ETH_ARP = 0x0806
ETH_IP = 0x0800
PORT_DNS = 53
PORT_WEB = 80

DMZ = IPNetwork('10.0.3.0/24')
INET = IPNetwork('10.0.1.0/24')
INTERNET = IPNetwork('10.0.2.0/24')

ALLOW_RULES = { INET : [INTERNET, DMZ, INET]}

ALL_ALLOWED = True

class Firewall_1(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Firewall_1, self).__init__(*args, **kwargs)
        self.states = set()


    def block_flow(self, datapath, match):
        ofproto = datapath.ofproto
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=1, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=[])

        datapath.send_msg(mod)



    def is_allowed(self, ip_src, ip_dst):
        if ALL_ALLOWED:
            return True

        for range1, allowed_dst in ALLOW_RULES.items():
            if IPAddress(ip_src) in range1:
                for range2 in allowed_dst:
                    if IPAddress(ip_dst) in range2:
                        return True 

        return False


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip4 = pkt.get_protocol(ipv4.ipv4)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)
            
        # IP Packets.......................................................................
        if ip4:
            self.logger.info("IP PACKET FIREWALL_1, ip_src=%s ip_dst=%s", ip4.src, ip4.dst)
            if self.is_allowed(ip4.src, ip4.dst):
                self.logger.info("PACKET ALLOWED")
                self.states.add((ip4.src, ip4.dst))
                return
            elif (ip4.dst, ip4.src) in self.states:
                self.logger.info("PACKET ALLOWED by states")
                return
            else :
                #DROP packets
                #add flow and packet_out with no actions
                self.logger.info("PACKET BLOCKED")
                match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_type = ETH_IP, dl_src=haddr_to_bin(src), dl_dst=haddr_to_bin(dst), nw_src=ip4.src, nw_dst=ip4.dst)
                self.block_flow(datapath, match)
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
                po_actions =[] # no actions = drop
            else:
                po_actions = [datapath.ofproto_parser.OFPActionOutput(outPort)]

            pkt_out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, 
                in_port=msg.in_port, data=data, actions=po_actions)
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
        match = ev.msg.match
        try:
            self.logger.info("match removed %s", match)
            self.states.remove((match['nw_src'], match['nw_dst']))
        except:
            pass
