from lxml import etree
from OFMsg import OFMsg


OF_TYPES = {
    10 : "packetIn",
    12 : "flowMod"
}
class Composition():
    def __init__(self, spec_filename):
        self.doc = etree.parse(spec_filename)
        self.module_list = {}
        self.load_modules(self.doc)
    
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
            print(conditions)
            for condition, value in conditions.iteritems():
                if not self.check_condition(condition, value, datapath_id, message):
                    print("not conditions ")
                    add_module = True # -------------------FALSEEE!!!!
                    break
            if add_module:
                modules.append(module)
        print(modules)
        return modules


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
        '''
            try:
                of_msg = OFMsg(datapath_id, message)
                if(OF_TYPES[of_msg.msg_type] in value):
                    print("events conditions!!!")
                    return True
            except:
                pass
        '''
        print('Condition %s value %s is False' % (condition, value))
        return False


    def resolution(self, msg, dpid):
        of_msg = OFMsg(dpid, msg)
        if(of_msg.msg_type == 12):
            print(of_msg.flowMod)