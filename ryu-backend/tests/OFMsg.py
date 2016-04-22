from ryu.ofproto import ofproto_v1_0 as ofproto
from ryu.ofproto import ofproto_parser
from ryu.ofproto.ofproto_v1_0_parser import *

class OFMsg(object):
	"""docstring for ofmsg"""
	def __init__(self, dpid, msg):
		super(OFMsg, self).__init__()
		self.msg = msg
		self.dpid = dpid
		self.version, self.msg_type, self.msg_len, self.xid = ofproto_parser.header(msg)
		print("header")
		print(ofproto_parser.header(msg))

		if self.msg_type == 10: #packet in
			self.packet_in_handler()
			print(self.packetIn)
		elif self.msg_type == 12: #flow_mod
			self.flow_mod_handler()

		
	def packet_in_handler(self):
		self.packetIn = OFPPacketIn.parser(self.dpid, self.version, self.msg_type, self.msg_len, self.xid, self.msg)


	def flow_mod_handler(self):
		print("flowmod!!")
		#match
		offset = ofproto.OFP_HEADER_SIZE
		match = OFPMatch.parse(self.msg, offset)

		#flow mod fields
		offset += ofproto.OFP_MATCH_SIZE
		(cookie, command, idle_timeout, hard_timeout, 
			priority, buffer_id, out_port, flags) = struct.unpack_from(ofproto.OFP_MATCH_PACK_STR, self.msg, offset)

		#actions
		actions = []
		offset = ofproto.OFP_FLOW_MOD_SIZE
		while offset < self.msg_len:
			action = OFPAction.parser(self.msg, offset)
			actions.append(action)
			offset += ofproto.OFP_ACTION_OUTPUT_SIZE
			print(len(action))

		self.flowMod = OFPFlowMod(self.dpid, match, cookie, command, idle_timeout, hard_timeout, priority,
			buffer_id, out_port, flags, actions)