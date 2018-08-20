package pcapdb.core.packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.buffer.ByteBufferLocater;
import pcapdb.core.buffer.MappedByteBufferLocater;
import pcapdb.core.frame.EthernetFrame;

import java.nio.ByteOrder;

public class EthernetPacket extends AbstractPacket {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public EthernetPacket(ByteBufferLocater byteBufferLocater, AbstractPacket abstractPacket) {
        super(byteBufferLocater,abstractPacket);
    }

    public String getDestinationAddress(){
        return this.byteBufferLocater.getByteString(EthernetFrame.DestinationAddressPosition,EthernetFrame.DestinationAddressLength, ByteOrder.LITTLE_ENDIAN);
    }

    public String getSourceAddress(){
        return this.byteBufferLocater.getByteString(EthernetFrame.SourceAddressPosition,EthernetFrame.SourceAddressLength,ByteOrder.LITTLE_ENDIAN);
    }

    public String getType(){
        return this.byteBufferLocater.getByteString(EthernetFrame.TypePosition,EthernetFrame.TypeLength,ByteOrder.LITTLE_ENDIAN);
    }

    @Override
    public ByteBufferLocater getPayload() {
        return new ByteBufferLocater(this.byteBufferLocater,this.byteBufferLocater.getBaseOffset()+ EthernetFrame.totalLength);
    }

    @Override
    public String toString() {
        logger.debug(new EthernetFrame().toString());
        return "EthernetPacket{" +
                "destinationAddress='" + getDestinationAddress() + '\'' +
                ", sourceAddress='" + getSourceAddress() + '\'' +
                ", type='" + getType() + '\'' +
                '}';
    }
}
