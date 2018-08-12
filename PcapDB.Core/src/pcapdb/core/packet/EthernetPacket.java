package pcapdb.core.packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.buffer.MappedByteBufferLocater;
import pcapdb.core.frame.EthernetFrame;

import java.nio.ByteOrder;

public class EthernetPacket extends AbstractPacket {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public EthernetPacket(MappedByteBufferLocater _mappedByteBufferLocater, AbstractPacket _packet) {
        super(_mappedByteBufferLocater,_packet);
    }

    public EthernetPacket(MappedByteBufferLocater _mappedByteBufferLocater) {
        super(_mappedByteBufferLocater);
    }

    public String getDestinationAddress(){
        return this.mappedByteBufferLocater.getByteString(EthernetFrame.DestinationAddressPosition,EthernetFrame.DestinationAddressLength, ByteOrder.LITTLE_ENDIAN);
    }

    public String getSourceAddress(){
        return this.mappedByteBufferLocater.getByteString(EthernetFrame.SourceAddressPosition,EthernetFrame.SourceAddressLength,ByteOrder.LITTLE_ENDIAN);
    }

    public String getType(){
        return this.mappedByteBufferLocater.getByteString(EthernetFrame.TypePosition,EthernetFrame.TypeLength,ByteOrder.LITTLE_ENDIAN);
    }

    @Override
    public MappedByteBufferLocater getPayload() {
        return new MappedByteBufferLocater(this.mappedByteBufferLocater,this.mappedByteBufferLocater.getBaseOffset()+ EthernetFrame.totalLength);
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
