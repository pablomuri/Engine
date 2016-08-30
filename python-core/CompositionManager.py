from lxml import etree
from OFMsg import OFMsg
from collections import OrderedDict
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
        self.modules_priority_dict = OrderedDict()
        self.load_modules(self.doc)
        self.resolution_messages_flowmod = {}
        self.resolution_messages_packetout = {}
        self.resolution_messages = {}
        self.fence_messages = {}
        self._messages_to_send = []
        self.messages_to_send = {}
        self.running_modules = {}

        

    # parsing the composition configuration
    def load_modules(self, doc):
        for df in doc.xpath('//Module'):
            self.module_list[df.attrib['id']] = {}
            module = self.module_list[df.attrib['id']]
            for sf in df.getchildren():
                for key in sf.attrib:
                    module[key] = sf.attrib[key].split()

        for df in doc.xpath('//ParallelCall'):
            for sf in df.getchildren():
                self.modules_priority_dict[sf.attrib['module']] = sf.attrib['priority']
            
        #sorting OrderedDict, minor first (highest priority minor number)
        self.modules_priority_dict = OrderedDict(sorted(self.modules_priority_dict.iteritems(), key=lambda x: x[1]))

        for df in doc.xpath('//ModuleCall'):
            if "notSendMessage" in df.attrib.keys():
                if df.attrib['notSendMessage'] == "true":
                    self.modules_priority_dict[df.attrib["module"]] = "notSendMessage"
                    
    
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
            add_module=True
            if add_module:
                modules.append(module)
        #print(modules)
        return modules


    def fence_msg_handler(self, mod_id, xid):
        self.fence_messages[mod_id] = xid
        if len(self.fence_messages) == len(self.module_list):
            #if all fence menssages has been received
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
                in_port = of_msg.packetIn.in_port
                print("in_port %s" % in_port)
                if str(in_port) in value:
                    return True
            else : 
                return False
        
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
        return False #should be False!!!

    #save the packet for a final resolution
    # if the packet is not packet_out or flowmod, or if is packet_out but the action is flood, it return false
    # and the packet will be sent directly
    def add_message(self, message, dpid):
        message_data = message[NetIDEOps.NetIDE_Header_Size:]
        decoded_header = NetIDEOps.netIDE_decode_header(message)
        module_id = decoded_header[NetIDEOps.NetIDE_header['MOD_ID']]
        of_msg = OFMsg(dpid, message_data)

        if(of_msg.msg_type == 14):
            if 'flow_mod' not in self.resolution_messages:
                self.resolution_messages['flow_mod'] = {}
            self.resolution_messages['flow_mod'][module_id] = (of_msg, message)
            return True

        elif(of_msg.msg_type == 13):
            if 'packet_out' not in self.resolution_messages:
                self.resolution_messages['packet_out'] = {}
            if not of_msg.actions:  
                self.resolution_messages['packet_out'][module_id] = (of_msg, message)
                return True
            elif of_msg.actions[0].port != ofproto.OFPP_FLOOD:
                self.resolution_messages['packet_out'][module_id] = (of_msg, message)
                return True

        return False


    def resolution(self, running_modules):
        #print("flows_mod messages: %d" % len(self.resolution_messages_flowmod))
        #print("packet_out messages: %d" % len(self.resolution_messages_packetout))
        self.running_modules = running_modules
        #self.resolution_messages['flow_mod'] = self.resolution_messages_flowmod
        #self.resolution_messages['packet_out'] = self.resolution_messages_packetout
        self._flow_mod_resolution()
        self._packet_out_resolution()


    def _flow_mod_resolution(self):
        if 'flow_mod' in self.resolution_messages:
            if self.resolution_messages['flow_mod']: #key 'flow_mod' exists
                messages_to_send = []
                messages_to_send_aux = []
                for module in self.modules_priority_dict.keys():
                    module_id = self.running_modules[module].get('module_id')
                    if module_id in self.resolution_messages['flow_mod']:
                        of_msg, message = self.resolution_messages['flow_mod'][module_id]
                        add_message = True
                        for aux_of_msg, aux_message in messages_to_send:
                            if(of_msg.match_equals(aux_of_msg)):
                                add_message = False
                        if add_message:
                            messages_to_send.append((of_msg, message))
                            if not self.modules_priority_dict[module] == "notSendMessage":
                                messages_to_send_aux.append((of_msg, message))

                self.messages_to_send['flow_mod'] = messages_to_send_aux
                self.resolution_messages['flow_mod'] = {}


    def _packet_out_resolution(self):
        if 'packet_out' in self.resolution_messages:
            if self.resolution_messages['packet_out']:
                messages_to_send = []
                messages_to_send_aux = []
                for module in self.modules_priority_dict.keys():
                    module_id = self.running_modules[module].get('module_id')
                    if module_id in self.resolution_messages['packet_out']:
                        of_msg, message = self.resolution_messages['packet_out'].get(module_id)
                        messages_to_send.append((of_msg, message))
                        if not self.modules_priority_dict[module] == "notSendMessage":
                            messages_to_send_aux.append((of_msg, message))
                        break

                self.messages_to_send['packet_out'] = messages_to_send_aux
                self.resolution_messages['packet_out'] = {}
