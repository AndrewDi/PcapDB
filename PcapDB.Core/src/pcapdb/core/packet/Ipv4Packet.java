package pcapdb.core.packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.buffer.MappedByteBufferLocater;
import pcapdb.core.frame.IPv4Frame;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteOrder;

public class Ipv4Packet extends AbstractPacket {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public Ipv4Packet(MappedByteBufferLocater _mappedByteBufferLocater,AbstractPacket _packet) {
        super(_mappedByteBufferLocater,_packet);
    }

    @Override
    public MappedByteBufferLocater getPayload() {
        return new MappedByteBufferLocater(this.mappedByteBufferLocater,this.mappedByteBufferLocater.getBaseOffset()+IPv4Frame.totalLength);
    }

    public AbstractPacket Decoder(){
        switch (this.getProtocol()){
            //Decode TCP Protocol
            case 6:
                TcpPacket tcpPacket = new TcpPacket(this.getPayload(),this);
                logger.debug(tcpPacket.toString());
                return tcpPacket.Decoder();

            default:
                return null;
        }
    }

    public int getVersion(){
        return this.mappedByteBufferLocater.getByte(IPv4Frame.VersionAndHeaderLengthPosition) >>4 & 0x0F;
    }

    public int getHeaderLength(){
        return this.mappedByteBufferLocater.getByte(IPv4Frame.VersionAndHeaderLengthPosition) & 0x0F;
    }

    public byte getDifferentiatedServices(){
        return this.mappedByteBufferLocater.getByte(IPv4Frame.DifferentiatedServicesPosition);
    }

    public int getTotalLength(){
        return this.mappedByteBufferLocater.getShort(IPv4Frame.TotalLengthPosition,ByteOrder.LITTLE_ENDIAN);
    }

    public int getId(){
        return this.mappedByteBufferLocater.getShort(IPv4Frame.IdPosition,ByteOrder.LITTLE_ENDIAN);
    }

    public String getFragmentOffsetAndFlags(){
        return this.mappedByteBufferLocater.getByteString(IPv4Frame.FragmentOffsetAndFlagsPosition,IPv4Frame.FragmentOffsetAndFlagsLength, ByteOrder.BIG_ENDIAN);
    }

    public int getTtL(){
        return this.mappedByteBufferLocater.getSingle(IPv4Frame.TtlPosition);
    }

    public int getProtocol(){
        return this.mappedByteBufferLocater.getSingle(IPv4Frame.ProtocolPosition);
    }

    public String getChecksum(){
        return this.mappedByteBufferLocater.getByteString(IPv4Frame.ChecksumPosition,IPv4Frame.ChecksumLength,ByteOrder.LITTLE_ENDIAN);
    }

    public InetAddress getSource(){
        try {
            return Inet4Address.getByAddress(this.mappedByteBufferLocater.getBytes(IPv4Frame.SourcePosition,IPv4Frame.AddressLength));
        } catch (UnknownHostException e) {
            logger.error(e.getLocalizedMessage());
        }
        return null;
    }

    public InetAddress getDestination(){
        try {
            return Inet4Address.getByAddress(this.mappedByteBufferLocater.getBytes(IPv4Frame.DestinationPosition,IPv4Frame.AddressLength));
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
        logger.debug(new IPv4Frame().toString());
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
