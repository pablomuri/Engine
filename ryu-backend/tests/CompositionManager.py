from lxml import etree
from OFMsg import OFMsg
from ryu.netide.netip import *

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
        self.resolution_messages = {}
        self.fence_messages = {}
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
                    #print("not conditions ")
                    add_module = True # -------------------FALSEEE!!!!
                    break
            if add_module:
                modules.append(module)
        #print(modules)
        return modules


    def fence_msg_handler(self, mod_id, xid):
        if not send_message:
            fence_messages[mod_id] = xid

    def check_condition(self, condition, value, datapath_id, message):
        if condition == 'datapaths':
            for dpid in value:
                if int(datapath_id,16) == int(dpid,16):
                    return True
        elif condition == 'inPort':
            of_msg = OFMsg(datapath_id, message)
            if(of_msg.msg_type == 10):
                #print("packet in")
                in_port = of_msg.packetIn.in_port
                #print(in_port)
                if str(in_port) in value:
                    return True
            else : 
                return True
        

        elif condition == 'events': 
            return True
        '''
            try:
                of_msg = OFMsg(datapath_id, message)
                if(OF_TYPES[of_msg.msg_type] in value):
                    #print("events conditions!!!")
                    return True
            except:
                pass
        '''
        #print('Condition %s value %s is False' % (condition, value))
        return False


    def add_message(self, message, dpid):
        message_data = message[NetIDEOps.NetIDE_Header_Size:]
        decoded_header = NetIDEOps.netIDE_decode_header(message)
        module_id = decoded_header[NetIDEOps.NetIDE_header['MOD_ID']]
        of_msg = OFMsg(dpid, message_data)

        if(of_msg.msg_type == 14):
            self.resolution_messages_flowmod[module_id] = (of_msg, message)
        elif(of_msg.msg_type == 13):
            self.resolution_messages_packetout[module_id] = (of_msg, message)
            #TODO: return messages if out_port flood ?
        else:
            self.resolution_messages[module_id] = (of_msg, message)

    def flow_mod_resolution(self, message, dpid):
        message_data = message[NetIDEOps.NetIDE_Header_Size:]
        decoded_header = NetIDEOps.netIDE_decode_header(message)
        module_id = decoded_header[NetIDEOps.NetIDE_header['MOD_ID']]
        of_msg = OFMsg(dpid, message_data)


        self.resolution_messages[module_id] = (of_msg, message)

        if len(self.resolution_messages) == len(self.module_list):
            of_msg1 = self.resolution_messages.values()[0][0]
            of_msg2 = self.resolution_messages.values()[1][0]

            print("match resolution.......................................")
            print(of_msg1.match)
            print(of_msg2.match)

            if((of_msg1.match['dl_dst'], of_msg1.match['dl_src'], of_msg1.match['in_port']) == 
                (of_msg2.match['dl_dst'], of_msg2.match['dl_src'], of_msg2.match['in_port'])):
                print("match equals")

                print("actions resolution..................")
                print(of_msg1.actions[0])
                print(of_msg2.actions[0])

                if of_msg1.actions[0].port == of_msg2.actions[0].port:
                    #flow are equals, return any msg
                    print("actions equals")
                    return self.resolution_messages.values()[0][1]

                else :
                    #return the message with flowmod no actions
                    for message_tuple in self.resolution_messages.values():
                        (of_msg, message) = message_tuple
                        if not of_msg.actions:
                            print("not actions (drop message)")
                            self.resolution_messages = {}
                            return message


    def packet_out_resolution(self, message, dpid):
        message_data = message[NetIDEOps.NetIDE_Header_Size:]
        decoded_header = NetIDEOps.netIDE_decode_header(message)
        module_id = decoded_header[NetIDEOps.NetIDE_header['MOD_ID']]
        of_msg = OFMsg(dpid, message_data)

        self.resolution_messages_packetout[module_id] = (of_msg, message)

        if len(self.resolution_messages_packetout) == len(self.module_list):
            of_msg1 = self.resolution_messages_packetout.values()[0][0]
            of_msg2 = self.resolution_messages_packetout.values()[1][0]

            if of_msg1.actions[0].port == of_msg2.actions[0].port:
                #packet_out are equals, return any msg
                print("packet_out actions equals")
                return self.resolution_messages.values()[0][1]

            else :
                #return the message with packet_out no actions
                for message_tuple in self.resolution_messages_packetout.values():
                    (of_msg, message) = message_tuple
                    if not of_msg.actions:
                        print("not actions (drop message)")
                        self.resolution_messages_packetout = {}
                        return message




