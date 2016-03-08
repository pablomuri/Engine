package eu.netide.core.globalfib;

import com.google.common.annotations.VisibleForTesting;
import eu.netide.core.api.IFIBManager;
import eu.netide.core.api.IShimManager;
import eu.netide.core.api.IShimMessageListener;
import eu.netide.lib.netip.Message;
import eu.netide.lib.netip.MessageType;
import eu.netide.lib.netip.OpenFlowMessage;
import org.apache.felix.scr.annotations.*;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.onosproject.net.topology.TopologyService;
import org.projectfloodlight.openflow.exceptions.OFParseError;
import org.projectfloodlight.openflow.protocol.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(immediate=true)
@Service
public class FIBManager implements IFIBManager, IShimMessageListener{
    private final OFMessageReader<OFMessage> reader;
    private final GlobalFIB globalFIB;

    private static final Logger log = LoggerFactory.getLogger(FIBManager.class);

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    @VisibleForTesting
    private IShimManager shimManager;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private TopologyService topologyService;

    public FIBManager()
    {
        reader = OFFactories.getGenericReader();
        globalFIB = new GlobalFIB();
    }

    @Activate
    protected void start()
    {
        log.info("FIBManager started.");
    }

    @Deactivate
    protected void stop()
    {
        log.info("FIBManager stopped.");
    }

    @Override
    public void OnShimMessage(Message message, String originId) {
        log.info("FIBManager received message from shim: " + message.getHeader().toString());
        if (message.getHeader().getMessageType() == MessageType.OPENFLOW) {
            OpenFlowMessage ofMessage = (OpenFlowMessage) message;
            if (ofMessage.getOfMessage().getType() == OFType.ECHO_REQUEST) {
                return;
            }
            // OpenFlow Message

            // Our API is broken

            ChannelBuffer bb = ChannelBuffers.copiedBuffer(message.getPayload());
            try {
                OFMessage ofmessage = reader.readFrom(bb);
                long datapathId = message.getHeader().getDatapathId();
                if (ofmessage instanceof OFFlowAdd) {
                    OFFlowAdd ofFlowAdd = (OFFlowAdd) ofmessage;

                    //globalFIB.addFlowMod(ofFlowAdd, datapathId);
                } if (ofmessage instanceof OFPacketIn) {
                    globalFIB.handlePacketIn((OFPacketIn) ofmessage, datapathId);
                }
            } catch (OFParseError ofParseError) {
                ofParseError.printStackTrace();
            }

        }
    }

    @Override
    public void handleMessage(Message message) {
        if (message.getHeader().getMessageType() == MessageType.OPENFLOW) {
            OpenFlowMessage ofMessage = (OpenFlowMessage) message;
            if (ofMessage.getOfMessage().getType() == OFType.FLOW_MOD) {
                globalFIB.addFlowMod(ofMessage);
            }
        }
        log.info("Relaying message to shim.");
        shimManager.sendMessage(message);
    }

    public void bindShimManager(IShimManager shimManager) {
        this.shimManager = shimManager;
    }
}
