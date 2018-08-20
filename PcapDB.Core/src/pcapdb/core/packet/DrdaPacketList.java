package pcapdb.core.packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.buffer.ByteBufferLocater;
import pcapdb.core.buffer.MappedByteBufferLocater;
import pcapdb.core.frame.DrdaCodePointType;

import java.nio.ByteOrder;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;

public class DrdaPacketList extends AbstractPacket {

    private LinkedHashMap<DrdaCodePointType,DrdaPacket> drdaPacketList;
    private int drdaPacketTotalLength;

    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public DrdaPacketList(ByteBufferLocater byteBufferLocater, AbstractPacket abstractPacket) {
        super(byteBufferLocater, abstractPacket);
        this.decoder();
    }

    public LinkedHashMap<DrdaCodePointType,DrdaPacket> getDrdaPacketList() {
        return drdaPacketList;
    }

    @Override
    public ByteBufferLocater getPayload() {
        return null;
    }


    private void decoder(){
        drdaPacketList = new LinkedHashMap<>();
        drdaPacketTotalLength = ((TcpPacket)this.parent).getPayloadLength();
        int drdaOffset = 0;
        int drdaPacketLength;
        while (drdaOffset < drdaPacketTotalLength) {
            drdaPacketLength = this.byteBufferLocater.getShort(drdaOffset, ByteOrder.LITTLE_ENDIAN);
            ByteBufferLocater drdaMappedByteBufferLocater = new ByteBufferLocater(this.byteBufferLocater, this.byteBufferLocater.getBaseOffset() + drdaOffset);
            drdaMappedByteBufferLocater.setLength(drdaPacketLength);
            DrdaPacket drdaPacket = new DrdaPacket(drdaMappedByteBufferLocater, this);
            this.drdaPacketList.put(drdaPacket.getDDMCodePoint(),drdaPacket);
            drdaOffset += drdaPacketLength;
        }
    }


    public String getDDMListString(){
        StringBuilder stringBuilder = new StringBuilder();
        this.drdaPacketList.forEach((drdaCodePointType, drdaPacket) -> {
            stringBuilder.append(drdaCodePointType);
            stringBuilder.append("|");
        });
        return stringBuilder.toString();
    }

    @Override
    public String toString() {
        return "DrdaPacketList{" +
                "drdaPacketList=" + drdaPacketList +
                ", drdaPacketTotalLength=" + drdaPacketTotalLength +
                '}';
    }
}
