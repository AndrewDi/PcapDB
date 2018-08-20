package pcapdb.core.packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.buffer.ByteBufferLocater;
import pcapdb.core.buffer.MappedByteBufferLocater;
import pcapdb.core.frame.IPv4Frame;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteOrder;

public class Ipv4Packet extends AbstractPacket {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    /**
     * @see <a href="http://www.ietf.org/rfc/rfc791.txt">rfc791</a>
     *     0                   1                   2                   3
     *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *    |Version|  IHL  |Type of Service|          Total Length         |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *    |         Identification        |Flags|      Fragment Offset    |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *    |  Time to Live |    Protocol   |         Header Checksum       |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *    |                       Source Address                          |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *    |                    Destination Address                        |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *    |                    Options                    |    Padding    |
     *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    public Ipv4Packet(ByteBufferLocater byteBufferLocater, AbstractPacket abstractPacket) {
        super(byteBufferLocater,abstractPacket);
    }

    @Override
    public ByteBufferLocater getPayload() {
        return new ByteBufferLocater(this.byteBufferLocater,this.byteBufferLocater.getBaseOffset()+this.getHeaderLength());
    }

    public AbstractPacket Decoder(){
        switch (this.getProtocol()){
            //Decode TCP Protocol
            case 6:
                TcpPacket tcpPacket = new TcpPacket(this.getPayload(),this);
                //logger.debug(tcpPacket.toString());
                return tcpPacket.Decoder();

            default:
                return null;
        }
    }

    public int getVersion(){
        return this.byteBufferLocater.getByte(IPv4Frame.VersionAndHeaderLengthPosition) >>4 & 0x0F;
    }

    public int getHeaderLength(){
        return (this.byteBufferLocater.getByte(IPv4Frame.VersionAndHeaderLengthPosition) & 0x0F)*4;
    }

    public byte getDifferentiatedServices(){
        return this.byteBufferLocater.getByte(IPv4Frame.DifferentiatedServicesPosition);
    }

    public int getTotalLength(){
        return this.byteBufferLocater.getShort(IPv4Frame.TotalLengthPosition,ByteOrder.LITTLE_ENDIAN);
    }

    public int getId(){
        return this.byteBufferLocater.getShort(IPv4Frame.IdPosition,ByteOrder.LITTLE_ENDIAN);
    }

    public String getFragmentOffsetAndFlags(){
        return this.byteBufferLocater.getByteString(IPv4Frame.FragmentOffsetAndFlagsPosition,IPv4Frame.FragmentOffsetAndFlagsLength, ByteOrder.BIG_ENDIAN);
    }

    public int getTtL(){
        return this.byteBufferLocater.getSingle(IPv4Frame.TtlPosition);
    }

    public int getProtocol(){
        return this.byteBufferLocater.getSingle(IPv4Frame.ProtocolPosition);
    }

    public String getChecksum(){
        return this.byteBufferLocater.getByteString(IPv4Frame.ChecksumPosition,IPv4Frame.ChecksumLength,ByteOrder.LITTLE_ENDIAN);
    }

    public InetAddress getSource(){
        try {
            return Inet4Address.getByAddress(this.byteBufferLocater.getBytes(IPv4Frame.SourcePosition,IPv4Frame.AddressLength));
        } catch (UnknownHostException e) {
            logger.error(e.getLocalizedMessage());
        }
        return null;
    }

    public InetAddress getDestination(){
        try {
            return Inet4Address.getByAddress(this.byteBufferLocater.getBytes(IPv4Frame.DestinationPosition,IPv4Frame.AddressLength));
        } catch (UnknownHostException e) {
            logger.error(e.getLocalizedMessage());
        }
        return null;
    }

    public int getPayloadLength(){
        return this.getTotalLength() - this.getHeaderLength();
    }

    @Override
    public String toString() {
        return "Ipv4Packet{" +
                "version=" + getVersion() +
                ", headerLength=" + getHeaderLength() +
                ", differentiatedServices=" + getDifferentiatedServices() +
                ", totalLength=" + getTotalLength() +
                ", id=" + getId() +
                ", fragmentOffsetAndFlags='" + getFragmentOffsetAndFlags() + '\'' +
                ", ttL=" + getTtL() +
                ", protocol=" + getProtocol() +
                ", checksum='" + getChecksum() + '\'' +
                ", source=" + getSource() +
                ", destination=" + getDestination() +
                ", payloadLength=" + getPayloadLength() +
                '}';
    }
}
