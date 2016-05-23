from lxml import etree
from OFMsg import OFMsg
from ryu.netide.netip import *
from ryu.ofproto import ofproto_v1_0 as ofproto

OF_TYPES = {
    10 : "packetIn",
    12 : "flowMod"
}

class Composition():
    def __init__(self, spec_filename):
        self.doc = etree.parse(spec_filename)
        self.module_list = {}
        self.load_modules(self.doc)
        self.resolution_messages_flowmod = {}
        self.resolution_messages_packetout = {}
        self.fence_messages = {}
        self.messages_to_send = []
    # parsing the composition configuration
    def load_modules(self, doc):
        for df in doc.xpath('//Module'):
            self.module_list[df.attrib['id']] = {}
            module = self.module_list[df.attrib['id']]
            for sf in df.getchildren():
                for key in sf.attrib:
                    module[key] = sf.attrib[key].split()

                    
    
    # this method returns the modules that are entitled to receive the event message
    def check_event_conditions(self, datapath_id, message):
        modules = [] 
        for module, conditions in self.module_list.iteritems():
            add_module = True
            #print(conditions)
            for condition, value in conditions.iteritems():
                if not self.check_condition(condition, value, datapath_id, message):
                    # print("not conditions ")
                    add_module = False
                    break
            if add_module:
                modules.append(module)
        #print(modules)
        return modules


    def fence_msg_handler(self, mod_id, xid):
        self.fence_messages[mod_id] = xid
        if len(self.fence_messages) == len(self.module_list):
            #if all fence menssages has been received
            self.resolution()
            self.fence_messages = {}
            return True
        else :
            return False


    def check_condition(self, condition, value, datapath_id, message):
        if condition == 'datapaths':
            for dpid in value:
                if int(datapath_id,16) == int(dpid,16):
                    return True
        elif condition == 'inPort':
            of_msg = OFMsg(datapath_id, message)
            if(of_msg.msg_type == 10):
                print("packet in")
                in_port = of_msg.packetIn.in_port
                print(in_port)
                if str(in_port) in value:
                    return True
            else : 
                return True
        

        elif condition == 'events': 
            return True
        
            try:
                of_msg = OFMsg(datapath_id, message)
                if(OF_TYPES[of_msg.msg_type] in value):
                    print("events conditions!!!")
                    return True
            except:
                pass
        
        #print('Condition %s value %s is False' % (condition, value))
        return False

    #save the packet for a final resolution
    # if the packet is not packet_out or flowmod, or if is packet_out but the action is flood, it return false
    # and the packet will be sent directly
    def add_message(self, message, dpid):
        message_data = message[NetIDEOps.NetIDE_Header_Size:]
        decoded_header = NetIDEOps.netIDE_decode_header(message)
        module_id = decoded_header[NetIDEOps.NetIDE_header['MOD_ID']]
        of_msg = OFMsg(dpid, message_data)

        if(of_msg.msg_type == 14):
            self.resolution_messages_flowmod[module_id] = (of_msg, message)
            return True

        elif(of_msg.msg_type == 13):
            if not of_msg.actions:  
                self.resolution_messages_packetout[module_id] = (of_msg, message)
                return True
            elif of_msg.actions[0].port != ofproto.OFPP_FLOOD:
                self.resolution_messages_packetout[module_id] = (of_msg, message)
                return True
            else: 
                return False

        else:
            return False


    def resolution(self):
        #print("flows_mod messages: %d" % len(self.resolution_messages_flowmod))
        #print("packet_out messages: %d" % len(self.resolution_messages_packetout))
        self.flow_mod_resolution()
        self.packet_out_resolution()

    #compare two flowmods and if there are not equals, it sends the flowmod from the firewall module
    def flow_mod_resolution(self):
    #TODO choose the flowmod from the highest priority module
        if len(self.resolution_messages_flowmod) == 1:

            print("one message to send")
            self.messages_to_send.append(self.resolution_messages_flowmod.values()[0][1])
        elif len(self.resolution_messages_flowmod) == 2:
            of_msg1 = self.resolution_messages_flowmod.values()[0][0]
            of_msg2 = self.resolution_messages_flowmod.values()[1][0]

            print("match resolution.......................................")

            if((of_msg1.match['dl_dst'], of_msg1.match['dl_src'], of_msg1.match['in_port'], of_msg1.match['dl_type']) == 
                (of_msg2.match['dl_dst'], of_msg2.match['dl_src'], of_msg2.match['in_port'], of_msg2.match['dl_type'])):
                print("match equals")
                print("actions resolution..................")

                try:
                    if of_msg1.actions[0].port == of_msg2.actions[0].port:
                        #flow are equals, return any msg
                        print("actions equals, added message to send")
                        self.messages_to_send.append(self.resolution_messages_flowmod.values()[0][1])
                    else : 
                        #it sends the two flow-mods
                        for (of_msg, message) in self.resolution_messages_flowmod.values():
                            self.messages_to_send.append(message)
                except:
                    #actions empty
                    #return the message with flowmod no actions
                    for (of_msg, message) in self.resolution_messages_flowmod.values():
                        if not of_msg.actions:
                            print("not actions (drop message)")
                            self.messages_to_send.append(message)
            else:
                #match not equals, send all flowmods
                for (of_msg, message) in self.resolution_messages_flowmod.values():
                    self.messages_to_send.append(message)

        self.resolution_messages_flowmod = {}


    def packet_out_resolution(self):
    #TODO choose the packet_out from the highest priority module
        if len(self.resolution_messages_packetout) == 1:
            #send message
            print("added of_msg packet_out to msgs_to_send")
            self.messages_to_send.append(self.resolution_messages_packetout.values()[0][1])
        elif len(self.resolution_messages_packetout) == 2:
            of_msg1 = self.resolution_messages_packetout.values()[0][0]
            of_msg2 = self.resolution_messages_packetout.values()[1][0]

            try:
                if of_msg1.actions[0].port == of_msg2.actions[0].port:
                    #packet_out are equals, return any msg
                    print("packet_out actions equals")
                    self.messages_to_send.append(self.resolution_messages_packetout.values()[0][1])
                else:
                    for (of_msg, message) in self.resolution_messages_packetout.values():
                        self.messages_to_send.append(message)

            except: 
            #actions empty
                #return the message with packet_out no actions
                for (of_msg, message) in self.resolution_messages_packetout.values():
                    if not of_msg.actions:
                        print("packet_out not actions (drop message)")
                        self.messages_to_send.append(message)

        self.resolution_messages_packetout = {}