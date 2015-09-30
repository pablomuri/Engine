package org.opendaylight.openflowjava.protocol.impl.deserialization.factories;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.opendaylight.openflowjava.protocol.api.extensibility.DeserializerRegistry;
import org.opendaylight.openflowjava.protocol.api.extensibility.OFDeserializer;
import org.opendaylight.openflowjava.protocol.api.extensibility.OFSerializer;
import org.opendaylight.openflowjava.protocol.api.extensibility.SerializerRegistry;
import org.opendaylight.openflowjava.protocol.api.keys.MessageCodeKey;
import org.opendaylight.openflowjava.protocol.api.keys.MessageTypeKey;
import org.opendaylight.openflowjava.protocol.api.util.EncodeConstants;
import org.opendaylight.openflowjava.protocol.impl.deserialization.NetIdeDeserializerRegistryImpl;
import org.opendaylight.openflowjava.protocol.impl.serialization.SerializerRegistryImpl;
import org.opendaylight.openflowjava.protocol.impl.util.BufferHelper;
import org.opendaylight.yang.gen.v1.urn.opendaylight.openflow.protocol.rev130731.GetFeaturesInput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.openflow.protocol.rev130731.GetFeaturesInputBuilder;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.UnpooledByteBufAllocator;

public class GetFeaturesInputFactoryTest {
	private OFDeserializer<GetFeaturesInput> factory;

    @Before
    public void startUp() {
        DeserializerRegistry registry = new NetIdeDeserializerRegistryImpl();
        registry.init();
        factory = registry.getDeserializer(new MessageCodeKey(EncodeConstants.OF13_VERSION_ID, 5, GetFeaturesInput.class));
    }
    
    @Test
    public void test() throws Exception{
    	GetFeaturesInput expectedMessage = createMessage();
    	SerializerRegistry registry = new SerializerRegistryImpl();
    	registry.init();
    	OFSerializer<GetFeaturesInput> serializer = registry.getSerializer(new MessageTypeKey<>(EncodeConstants.OF13_VERSION_ID, GetFeaturesInput.class));
    	ByteBuf originalBuffer = UnpooledByteBufAllocator.DEFAULT.buffer();
    	serializer.serialize(expectedMessage, originalBuffer);
    	
    	// TODO: Skipping first 4 bytes due to the way deserializer is implemented 
    	// Skipping version, type and length from OF header
    	originalBuffer.skipBytes(4);
    	GetFeaturesInput deserializedMessage = BufferHelper.deserialize(factory, originalBuffer);
    	Assert.assertEquals("Wrong version", expectedMessage.getVersion(), deserializedMessage.getVersion());
    	Assert.assertEquals("Wrong XId", expectedMessage.getXid(), deserializedMessage.getXid());
    }
    
    private GetFeaturesInput createMessage() throws Exception{
    	GetFeaturesInputBuilder builder = new GetFeaturesInputBuilder();
        BufferHelper.setupHeader(builder, EncodeConstants.OF13_VERSION_ID);
        return builder.build();
    }
}