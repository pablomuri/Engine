from ryu.ofproto import ofproto_v1_0 as ofproto
from ryu.ofproto.ofproto_v1_0_parser import *

class ofmsg(object):
	"""docstring for ofmsg"""
	def __init__(self, msg, dpid):
		super(ofmsg, self).__init__()
		version, msg_type, msg_len, xid = ryu.ofproto.ofproto_parser.header(msg)

		if of_type == 10:
			self.packetIn = OFPPacketIn.parser(dpid, version, msg_type, msg_len, xid, msg)

		
