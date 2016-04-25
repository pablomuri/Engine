from ryu.ofproto import ofproto_v1_0 as ofproto
from ryu.ofproto import ofproto_parser
from ryu.ofproto.ofproto_v1_0_parser import OFPPacketIn,OFPMatch,OFPAction
import struct

class OFMsg(object):
	"""docstring for ofmsg"""
	def __init__(self, dpid, msg):
		super(OFMsg, self).__init__()
		self.msg = msg
		self.dpid = dpid
		print("header")
		print(ofproto_parser.header(msg))
		self.version, self.msg_type, self.msg_len, self.xid = ofproto_parser.header(msg)
		
	
		if self.msg_type == 10: #packet in
			self.packet_in_handler()
			print(self.packetIn)
		elif self.msg_type == 14: #flow_mod
			self.flow_mod_handler()

		
	def packet_in_handler(self):
		self.packetIn = OFPPacketIn.parser(self.dpid, self.version, self.msg_type, self.msg_len, self.xid, self.msg)


	def flow_mod_handler(self):
		print("flowmod!!.......................................................................................")
		#match
		offset = ofproto.OFP_HEADER_SIZE
		self.match = OFPMatch.parse(self.msg, offset)

		#flow mod fields
		offset += ofproto.OFP_MATCH_SIZE	
		(self.cookie, self.command, self.idle_timeout, self.hard_timeout, 
			self.priority, self.buffer_id, self.out_port, self.flags) = struct.unpack_from(ofproto.OFP_FLOW_MOD_PACK_STR0, self.msg, offset)

		#actions
		self.actions = []
		offset = ofproto.OFP_FLOW_MOD_SIZE
		while offset < self.msg_len:
			action = OFPAction.parser(self.msg, offset)
			(type_, len_) = struct.unpack_from('!HH', self.msg, offset)
			print(len_)
			self.actions.append(action)
			offset += len_