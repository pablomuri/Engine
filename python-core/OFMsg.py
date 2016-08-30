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
		self.version, self.msg_type, self.msg_len, self.xid = ofproto_parser.header(msg)
		
	
		if self.msg_type == 10: #packet in
			self.packet_in_handler()
		elif self.msg_type == 13: #packet out
			self.packet_out_handler()
		elif self.msg_type == 14: #flow_mod
			self.flow_mod_handler()

		
	def packet_in_handler(self):
		self.packetIn = OFPPacketIn.parser(self.dpid, self.version, self.msg_type, self.msg_len, self.xid, self.msg)

	def packet_out_handler(self):
		self.actions = self.actions_decoder(ofproto.OFP_PACKET_OUT_SIZE)

	def flow_mod_handler(self):
		#match
		offset = ofproto.OFP_HEADER_SIZE
		self.match = OFPMatch.parse(self.msg, offset)

		#flow mod fields
		offset += ofproto.OFP_MATCH_SIZE	
		(self.cookie, self.command, self.idle_timeout, self.hard_timeout, 
			self.priority, self.buffer_id, self.out_port, self.flags) = struct.unpack_from(ofproto.OFP_FLOW_MOD_PACK_STR0, self.msg, offset)

		#actions
		self.actions = self.actions_decoder(ofproto.OFP_FLOW_MOD_SIZE)


	def actions_decoder(self, offset):
		actions = []
		while offset < self.msg_len:
			action = OFPAction.parser(self.msg, offset)
			(type_, len_) = struct.unpack_from('!HH', self.msg, offset)
			actions.append(action)
			offset += len_
		return actions

	def match_equals(self, aux_of_msg):
		return ((self.match['dl_dst'], self.match['dl_src'], self.match['in_port'], self.match['dl_type']) == 
                (aux_of_msg.match['dl_dst'], aux_of_msg.match['dl_src'], aux_of_msg.match['in_port'], aux_of_msg.match['dl_type']))

	def packet_out_equals(self, aux_of_msg):
		if (self.msg_type, aux_of_msg.msg_type) == (13, 13):
			if self.actions and aux_of_msg.actions:
				return (self.actions[0].port == aux_of_msg.actions[0].port)
			else:
				return False
		else :
			return False

	def __repr__(self):
		if self.msg_type == 14:
			return str(ofproto_parser.header(self.msg)) + str(self.match) + str(self.actions)
		elif self.msg_type == 13:
			return str(ofproto_parser.header(self.msg)) + str(self.actions)
		else:
			return str(ofproto_parser.header(self.msg))