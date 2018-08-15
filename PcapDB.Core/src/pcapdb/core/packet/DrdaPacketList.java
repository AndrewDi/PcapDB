package pcapdb.core.packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.buffer.MappedByteBufferLocater;

import java.nio.ByteOrder;
import java.util.LinkedList;
import java.util.List;

public class DrdaPacketList extends AbstractPacket {

    private List<DrdaPacket> drdaPacketList;
    private int drdaPacketTotalLength;

    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public DrdaPacketList(MappedByteBufferLocater mappedByteBufferLocater, AbstractPacket abstractPacket) {
        super(mappedByteBufferLocater, abstractPacket);
        this.decoder();
    }

    public List<DrdaPacket> getDrdaPacketList() {
        return drdaPacketList;
    }

    @Override
    public MappedByteBufferLocater getPayload() {
        return null;
    }


    private void decoder(){
        drdaPacketList = new LinkedList<>();
        drdaPacketTotalLength = ((TcpPacket)this.parent).getPayloadLength();
        int drdaOffset = 0;
        int drdaPacketLength;
        while(true){
            if(drdaOffset>=drdaPacketTotalLength)
                break;
            drdaPacketLength = this.mappedByteBufferLocater.getShort(drdaOffset, ByteOrder.LITTLE_ENDIAN);
            MappedByteBufferLocater drdaMappedByteBufferLocater = new MappedByteBufferLocater(this.mappedByteBufferLocater,this.mappedByteBufferLocater.getBaseOffset()+drdaOffset);
            drdaMappedByteBufferLocater.setLength(drdaPacketLength);
            DrdaPacket drdaPacket = new DrdaPacket(drdaMappedByteBufferLocater,this);
            this.drdaPacketList.add(drdaPacket);
            drdaOffset+=drdaPacketLength;
        }
        logger.debug("Discover {} DrdaPacket",drdaPacketList.size());
    }

    @Override
    public String toString() {
        return "DrdaPacketList{" +
                "drdaPacketList=" + drdaPacketList +
                ", drdaPacketTotalLength=" + drdaPacketTotalLength +
                '}';
    }
}
