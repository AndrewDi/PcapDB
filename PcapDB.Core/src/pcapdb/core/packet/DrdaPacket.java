package pcapdb.core.packet;

import pcapdb.core.buffer.MappedByteBufferLocater;
import pcapdb.core.frame.DrdaCodePointType;
import pcapdb.core.frame.DrdaFrame;

import java.nio.ByteOrder;

public class DrdaPacket extends AbstractPacket {

    public DrdaPacket(MappedByteBufferLocater _mappedByteBufferLocater, AbstractPacket _packet) {
        super(_mappedByteBufferLocater, _packet);
    }

    @Override
    public MappedByteBufferLocater getPayload() {
        return null;
    }

    public int getDDMLength(){
        return this.mappedByteBufferLocater.getShort(DrdaFrame.DDMLengthPosition, ByteOrder.LITTLE_ENDIAN);
    }

    public String getDDMMagic(){
        return this.mappedByteBufferLocater.getByteStrig(DrdaFrame.DDMMagicPosition);
    }

    public byte getDDMFormat(){
        return this.mappedByteBufferLocater.getByte(DrdaFrame.DDMFormatPosition);
    }

    public int getDDMCorrelId(){
        return this.mappedByteBufferLocater.getShort(DrdaFrame.DDMCorrelIdPosition,ByteOrder.LITTLE_ENDIAN);
    }

    public int getDDMLength2(){
        return this.mappedByteBufferLocater.getShort(DrdaFrame.DDMLength2Position, ByteOrder.LITTLE_ENDIAN);
    }

    public DrdaCodePointType getDDMCodePoint(){
        return DrdaCodePointType.valueOf(this.mappedByteBufferLocater.getShort(DrdaFrame.DDMCodePointPosition,ByteOrder.LITTLE_ENDIAN));
    }

    @Override
    public String toString() {
        return "DrdaPacket{" +
                "DDMLength=" + getDDMLength() +
                ", DDMMagic='" + getDDMMagic() + '\'' +
                ", DDMFormat=" + getDDMFormat() +
                ", DDMCorrelId=" + getDDMCorrelId() +
                ", DDMLength2=" + getDDMLength2() +
                ", DDMCodePoint=" + getDDMCodePoint() +
                '}';
    }
}
