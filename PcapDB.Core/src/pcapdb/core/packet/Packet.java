package pcapdb.core.packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.buffer.MappedByteBufferLocater;
import pcapdb.core.frame.PacketFrame;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

public class Packet extends AbstractPacket {
    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public Packet(MappedByteBufferLocater mappedByteBufferLocater) {
        super(mappedByteBufferLocater);
    }

    @Override
    public MappedByteBufferLocater getPayload() {
        return new MappedByteBufferLocater(this.mappedByteBufferLocater,this.mappedByteBufferLocater.getBaseOffset()+PacketFrame.totalLength);
    }

    public long getGMTtime(){
         return this.mappedByteBufferLocater.getUnsignedInt(PacketFrame.GMTTimePosition);
    }

    public int getMicroTime(){
        return this.mappedByteBufferLocater.getInt(PacketFrame.MicroTimePosition);
    }

    public LocalDateTime getFullArrivalTime(){
        return LocalDateTime.ofEpochSecond(getGMTtime(),getMicroTime()*1000, ZoneOffset.of("+8"));
    }

    public int getCapLen(){
        return this.mappedByteBufferLocater.getInt(PacketFrame.CapLenPosition);
    }

    public int getLen(){
        return this.mappedByteBufferLocater.getInt(PacketFrame.LenPosition);
    }

    public MappedByteBufferLocater getNextPacket(){

        //Every packet has 16 bytes
        int nextIndex = this.mappedByteBufferLocater.getBaseOffset()+this.getCapLen()+16;
        return new MappedByteBufferLocater(this.mappedByteBufferLocater,nextIndex);
    }

    public AbstractPacket Decoder(){

        //Only support Ethernet Packet
        EthernetPacket ethernetPacket = new EthernetPacket(this.getPayload(),this);
        //logger.debug(ethernetPacket.toString());
        switch (ethernetPacket.getType()){
            case "0800":
                Ipv4Packet ipv4Packet = new Ipv4Packet(ethernetPacket.getPayload(),ethernetPacket);
                //logger.debug(ipv4Packet.toString());
                return ipv4Packet.Decoder();
            case "86DD":
                //Ipv6 Packet
            default:
                return null;
        }
    }

    @Override
    public String toString() {
        return "Packet{" +
                "GMTtime="+this.getGMTtime() +
                ", MicroTime="+this.getMicroTime() +
                ", CapLen="+this.getCapLen() +
                ", Len="+this.getLen() +
                ", FullArrivalTime="+this.getFullArrivalTime() +
                '}';
    }
}
