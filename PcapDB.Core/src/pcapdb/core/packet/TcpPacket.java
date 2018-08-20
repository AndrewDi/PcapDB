package pcapdb.core.packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.buffer.ByteBufferLocater;
import pcapdb.core.buffer.MappedByteBufferLocater;
import pcapdb.core.frame.TcpFrame;

import java.nio.ByteOrder;

public class TcpPacket extends AbstractPacket {

    /**
     * @see <a href="http://www.ietf.org/rfc/rfc793.txt">rfc793</a>
     *
     *     0                   1                   2                   3
     *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *    |          Source Port          |       Destination Port        |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *    |                        Sequence Number                        |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *    |                    Acknowledgment Number                      |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *    |  Data |           |U|A|P|R|S|F|                               |
     *    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
     *    |       |           |G|K|H|T|N|N|                               |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *    |           Checksum            |         Urgent Pointer        |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *    |                    Options                    |    Padding    |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *    |                             data                              |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public TcpPacket(ByteBufferLocater byteBufferLocater, AbstractPacket abstractPacket) {
        super(byteBufferLocater, abstractPacket);
    }

    public int HeaderMinimumLength = 20;

    public String getKey(){
        Ipv4Packet ipv4Packet = (Ipv4Packet)this.getParent();
        return String.format("%s|%d|%s|%d",ipv4Packet.getSource().getHostAddress(),this.getSourcePort(),ipv4Packet.getDestination().getHostAddress(),this.getDestinationPort());
    }

    public String getReversalKey(){
        Ipv4Packet ipv4Packet = (Ipv4Packet)this.getParent();
        return String.format("%s|%d|%s|%d",ipv4Packet.getDestination().getHostAddress(),this.getDestinationPort(),ipv4Packet.getSource().getHostAddress(),this.getSourcePort());
    }

    public int getSourcePort(){
        return this.byteBufferLocater.getShort(TcpFrame.SourcePortPosition, ByteOrder.LITTLE_ENDIAN);
    }

    public int getDestinationPort(){
        return this.byteBufferLocater.getShort(TcpFrame.DestinationPortPosition, ByteOrder.LITTLE_ENDIAN);
    }

    public long getSequenceNumber(){
        return this.byteBufferLocater.getUnsignedInt(TcpFrame.SequenceNumberPosition,ByteOrder.LITTLE_ENDIAN);
    }

    public long getAcknowledgmentNumber(){
        return this.byteBufferLocater.getUnsignedInt(TcpFrame.AckNumberPosition,ByteOrder.LITTLE_ENDIAN);
    }

    public int getDataOffsetAndFlags(){
        return this.byteBufferLocater.getShort(TcpFrame.DataOffsetAndFlagsPosition,ByteOrder.LITTLE_ENDIAN);
    }

    public int getDataOffset(){
        return (this.getDataOffsetAndFlags() >> 12) & 0x0F;
    }

    public int getWindowSize(){
        return this.byteBufferLocater.getShort(TcpFrame.WindowSizePosition,ByteOrder.LITTLE_ENDIAN);
    }

    public int getChecksum(){
        return this.byteBufferLocater.getShort(TcpFrame.ChecksumPosition,ByteOrder.LITTLE_ENDIAN);
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
        return this.getDataOffset()*4;
    }

    @Override
    public ByteBufferLocater getPayload() {
        return new ByteBufferLocater(this.byteBufferLocater,this.byteBufferLocater.getBaseOffset()+this.getHeaderLength());
    }

    public AbstractPacket Decoder() {
        if(this.getPayloadLength()<4){
            return null;
        }
        ByteBufferLocater payloadMappedByteBufferLocater = this.getPayload();
        int drdaLength = payloadMappedByteBufferLocater.getShort(0,ByteOrder.LITTLE_ENDIAN);
        if(this.getPayloadLength()<drdaLength)
            return null;
        String magic = payloadMappedByteBufferLocater.getByteStrig(2);
        //0xD0 means this a DRDA packet
        if(magic.equals("D0")){
            DrdaPacketList drdaPacketList = new DrdaPacketList(payloadMappedByteBufferLocater,this);
            //logger.debug(drdaPacketList.toString());
            return drdaPacketList;
        }
        return this;
    }

    public int getPayloadLength(){
        return ((Ipv4Packet)this.parent).getPayloadLength()-this.getHeaderLength();
    }

    @Override
    public String toString() {
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
