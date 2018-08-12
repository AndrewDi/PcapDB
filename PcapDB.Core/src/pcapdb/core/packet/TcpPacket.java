package pcapdb.core.packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.buffer.MappedByteBufferLocater;
import pcapdb.core.frame.TcpFrame;

import java.nio.ByteOrder;

public class TcpPacket extends AbstractPacket {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public TcpPacket(MappedByteBufferLocater _mappedByteBufferLocater, AbstractPacket _packet) {
        super(_mappedByteBufferLocater, _packet);
    }

    public int HeaderMinimumLength = 20;

    public int getSourcePort(){
        return this.mappedByteBufferLocater.getShort(TcpFrame.SourcePortPosition, ByteOrder.LITTLE_ENDIAN);
    }

    public int getDestinationPort(){
        return this.mappedByteBufferLocater.getShort(TcpFrame.DestinationPortPosition, ByteOrder.LITTLE_ENDIAN);
    }

    public long getSequenceNumber(){
        return this.mappedByteBufferLocater.getUnsignedInt(TcpFrame.SequenceNumberPosition,ByteOrder.LITTLE_ENDIAN);
    }

    public long getAcknowledgmentNumber(){
        return this.mappedByteBufferLocater.getUnsignedInt(TcpFrame.AckNumberPosition,ByteOrder.LITTLE_ENDIAN);
    }

    public int getDataOffsetAndFlags(){
        return this.mappedByteBufferLocater.getShort(TcpFrame.DataOffsetAndFlagsPosition,ByteOrder.LITTLE_ENDIAN);
    }

    public int getDataOffset(){
        return (this.getDataOffsetAndFlags() >> 12) & 0x0F;
    }

    public int getWindowSize(){
        return this.mappedByteBufferLocater.getShort(TcpFrame.WindowSizePosition,ByteOrder.LITTLE_ENDIAN);
    }

    public int getChecksum(){
        return this.mappedByteBufferLocater.getShort(TcpFrame.ChecksumPosition,ByteOrder.LITTLE_ENDIAN);
    }

    public boolean getValidChecksum(){
        return true;
    }

    public int getAllFlags(){
        return this.getDataOffsetAndFlags() & 0x1FF;
    }

    public boolean isUrg(){
        return (this.getAllFlags() & TcpFrame.TCP_URG_MASK) !=0;
    }

    public boolean isAck(){
        return (this.getAllFlags() & TcpFrame.TCP_ACK_MASK) !=0;
    }

    public boolean isPsh(){
        return (this.getAllFlags() & TcpFrame.TCP_PSH_MASK) !=0;
    }

    public boolean isRst(){
        return (this.getAllFlags() & TcpFrame.TCP_RST_MASK) !=0;
    }

    public boolean isSyn(){
        return (this.getAllFlags() & TcpFrame.TCP_SYN_MASK) !=0;
    }

    public boolean isFin(){
        return (this.getAllFlags() & TcpFrame.TCP_FIN_MASK) !=0;
    }

    public boolean isECN(){
        return (this.getAllFlags() & TcpFrame.TCP_ECN_MASK) !=0;
    }

    public boolean isCWR(){
        return (this.getAllFlags() & TcpFrame.TCP_CWR_MASK) !=0;
    }

    public boolean isNS(){
        return (this.getAllFlags() & TcpFrame.TCP_NS_MASK) !=0;
    }

    public int getHeaderLength(){
        return this.mappedByteBufferLocater.getByte(TcpFrame.DataOffsetAndFlagsPosition) << 2 & 0x0F;
    }

    @Override
    public MappedByteBufferLocater getPayload() {
        return new MappedByteBufferLocater(this.mappedByteBufferLocater,this.mappedByteBufferLocater.getBaseOffset()+this.getHeaderLength());
    }

    public AbstractPacket Decoder() {
        logger.debug(getPayloadLength()+"");
        if(this.getPayloadLength()<4){
            return null;
        }
        byte magic = this.mappedByteBufferLocater.getByte(TcpFrame.totalLength+2);
        if(magic==0xd0){
            DRDAPacket drdaPacket = new DRDAPacket(this.getPayload(),this);
            return drdaPacket;
        }
        return null;
    }

    public int getPayloadLength(){
        return ((Ipv4Packet)this.parent).getPayloadLength()-TcpFrame.totalLength;
    }

    @Override
    public String toString() {
        logger.debug(new TcpFrame().toString());
        return "TcpPacket{" +
                "sourcePort=" + getSourcePort() +
                ", destinationPort=" + getDestinationPort() +
                ", sequenceNumber=" + getSequenceNumber() +
                ", acknowledgmentNumber=" + getAcknowledgmentNumber() +
                ", dataOffsetAndFlags=" + getDataOffsetAndFlags() +
                ", dataOffset=" + getDataOffset() +
                ", windowSize=" + getWindowSize() +
                ", checksum=" + getChecksum() +
                ", validChecksum=" + getValidChecksum() +
                ", allFlags=" + getAllFlags() +
                ", urg=" + isUrg() +
                ", ack=" + isAck() +
                ", psh=" + isPsh() +
                ", rst=" + isRst() +
                ", syn=" + isSyn() +
                ", fin=" + isFin() +
                ", ECN=" + isECN() +
                ", CWR=" + isCWR() +
                ", NS=" + isNS() +
                ", headerLength=" + getHeaderLength() +
                ", payloadLength=" + getPayloadLength() +
                '}';
    }
}
