package pcapdb.core.packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.buffer.ByteBufferLocater;
import pcapdb.core.buffer.MappedByteBufferLocater;
import pcapdb.core.frame.PacketFrame;

import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

public class Packet extends AbstractPacket {
    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    private Long GMTTime=null;
    private Integer MicroTime = null;
    private Integer CapLen = null;
    private Integer Len = null;

    public Packet(ByteBufferLocater mappedByteBufferLocater) {
        super(mappedByteBufferLocater);
    }

    public Packet(ByteBuffer byteBuffer,long gmtTime,int microTime,int capLen,int len){
        this(new ByteBufferLocater(byteBuffer,0));
        this.GMTTime = gmtTime;
        this.MicroTime = microTime;
        this.CapLen = capLen;
        this.Len = len;
    }

    @Override
    public ByteBufferLocater getPayload() {
        return this.GMTTime == null ? new ByteBufferLocater(this.byteBufferLocater,this.byteBufferLocater.getBaseOffset()+PacketFrame.totalLength):
                new ByteBufferLocater(this.byteBufferLocater,this.byteBufferLocater.getBaseOffset());
    }

    public long getGMTtime(){
        return this.GMTTime == null ?  this.byteBufferLocater.getUnsignedInt(PacketFrame.GMTTimePosition):this.GMTTime;
    }

    public int getMicroTime(){
        return this.MicroTime == null ? this.byteBufferLocater.getInt(PacketFrame.MicroTimePosition):this.MicroTime;
    }

    public LocalDateTime getFullArrivalTime(){
        return LocalDateTime.ofEpochSecond(getGMTtime(),getMicroTime()*1000, ZoneOffset.of("+8"));
    }

    public int getCapLen(){
        return this.CapLen == null? this.byteBufferLocater.getInt(PacketFrame.CapLenPosition):this.CapLen;
    }

    public int getLen(){
        return this.Len == null ? this.byteBufferLocater.getInt(PacketFrame.LenPosition):this.Len;
    }

    public ByteBufferLocater getNextPacket(){

        //Every packet has 16 bytes
        int nextIndex = this.byteBufferLocater.getBaseOffset()+this.getCapLen()+16;
        return new ByteBufferLocater(this.byteBufferLocater,nextIndex);
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
