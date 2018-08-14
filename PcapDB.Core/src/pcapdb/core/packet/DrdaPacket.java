package pcapdb.core.packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.buffer.MappedByteBufferLocater;
import pcapdb.core.frame.DrdaCodePointType;
import pcapdb.core.frame.DrdaFrame;
import pcapdb.core.frame.SVRCODLevel;
import pcapdb.core.frame.UOWDSP;

import java.nio.ByteOrder;
import java.util.LinkedList;
import java.util.List;

public class DrdaPacket extends AbstractPacket {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    private List<DrdaDDMParameter> drdaDDMParameters;

    public DrdaPacket(MappedByteBufferLocater _mappedByteBufferLocater, AbstractPacket _packet) {
        super(_mappedByteBufferLocater, _packet);
    }

    public List<DrdaDDMParameter> getDrdaDDMParameters() {
        if (this.drdaDDMParameters == null) this.drdaDDMParameters = new LinkedList<>();
        if (this.drdaDDMParameters.size() > 0) return this.drdaDDMParameters;

        int offset = DrdaFrame.totalLength;
        while (offset < this.mappedByteBufferLocater.getLength() - DrdaFrame.totalLength) {
            int length = this.mappedByteBufferLocater.getShort(offset, ByteOrder.LITTLE_ENDIAN);
            DrdaCodePointType drdaCodePointType = DrdaCodePointType.valueOf(this.mappedByteBufferLocater.getShort(offset + DrdaFrame.DDMLengthLength, ByteOrder.LITTLE_ENDIAN));
            if (length == 0 || getDDMCodePoint() == DrdaCodePointType.SQLSTT || getDDMCodePoint() == DrdaCodePointType.QRYDTA ||
                    getDDMCodePoint() == DrdaCodePointType.QRYDSC) {
                length = this.mappedByteBufferLocater.getLength() - DrdaFrame.totalLength - (DrdaFrame.DDMParameterLengthLength + DrdaFrame.DDMParameterCodePointLength);
            }

            DrdaDDMParameter drdaDDMParameter = new DrdaDDMParameter();
            drdaDDMParameter.setLength(length);
            drdaDDMParameter.setDrdaCodePointType(drdaCodePointType);

            int startIndex = offset + DrdaFrame.DDMParameterLengthLength + DrdaFrame.DDMParameterCodePointLength;
            int strlength = length;
            switch (drdaCodePointType) {
                //Generate Data
                case DATA:
                case QRYDTA:
                    strlength -= 1;
                    drdaDDMParameter.setData(this.mappedByteBufferLocater.getUTF8String(startIndex, strlength).trim());
                    break;
                case PRDDTA:
                    startIndex+=1;
                    strlength -= 4;
                    drdaDDMParameter.setData(this.mappedByteBufferLocater.getEbcdicString(startIndex, strlength).trim());
                    break;
                case RDBACCCL:
                case QRYPRCTYP:
                    drdaDDMParameter.setData(DrdaCodePointType.valueOf(this.mappedByteBufferLocater.getShort(startIndex, ByteOrder.LITTLE_ENDIAN)));
                    break;
                case PKGNAMCSN:
                     strlength -= 16;
                     drdaDDMParameter.setData(this.mappedByteBufferLocater.getEbcdicString(startIndex, strlength).trim());
                     break;
                case PKGSNLST:
                    strlength-=24;
                    startIndex+=4;
                    drdaDDMParameter.setData(this.mappedByteBufferLocater.getEbcdicString(startIndex, strlength).trim());
                    break;
                case RSLSETFLG:
                    strlength-=1;
                    drdaDDMParameter.setData(this.mappedByteBufferLocater.getByteString(startIndex,strlength,ByteOrder.LITTLE_ENDIAN).trim());
                    break;
                case QRYBLKSZ:
                case MAXRSLCNT:
                case MAXBLKEXT:
                    drdaDDMParameter.setData(this.mappedByteBufferLocater.getShort(startIndex, ByteOrder.LITTLE_ENDIAN));
                    break;
                case SVRCOD:
                    drdaDDMParameter.setData(SVRCODLevel.valueOf(this.mappedByteBufferLocater.getShort(startIndex, ByteOrder.LITTLE_ENDIAN)));
                    break;
                case UOWDSP:
                    drdaDDMParameter.setData(UOWDSP.valueOf(this.mappedByteBufferLocater.getByte(startIndex)));
                    break;
                default:
                    strlength -= 4;
                    drdaDDMParameter.setData(this.mappedByteBufferLocater.getEbcdicString(startIndex, strlength).trim());
                    break;

            }
            this.drdaDDMParameters.add(drdaDDMParameter);
            offset += length;
        }
        return this.drdaDDMParameters;
    }

    @Override
    public MappedByteBufferLocater getPayload() {
        return null;
    }

    public int getDDMLength() {
        return this.mappedByteBufferLocater.getShort(DrdaFrame.DDMLengthPosition, ByteOrder.LITTLE_ENDIAN);
    }

    public String getDDMMagic() {
        return this.mappedByteBufferLocater.getByteStrig(DrdaFrame.DDMMagicPosition);
    }

    public byte getDDMFormat() {
        return this.mappedByteBufferLocater.getByte(DrdaFrame.DDMFormatPosition);
    }

    public int getDDMCorrelId() {
        return this.mappedByteBufferLocater.getShort(DrdaFrame.DDMCorrelIdPosition, ByteOrder.LITTLE_ENDIAN);
    }

    public int getDDMLength2() {
        return this.mappedByteBufferLocater.getShort(DrdaFrame.DDMLength2Position, ByteOrder.LITTLE_ENDIAN);
    }

    public DrdaCodePointType getDDMCodePoint() {
        return DrdaCodePointType.valueOf(this.mappedByteBufferLocater.getShort(DrdaFrame.DDMCodePointPosition, ByteOrder.LITTLE_ENDIAN));
    }

    @Override
    public String toString() {
        return "DrdaPacket{" +
                "drdaDDMParameters=" + this.getDrdaDDMParameters() +
                ", DDMLength=" + getDDMLength() +
                ", DDMMagic='" + getDDMMagic() + '\'' +
                ", DDMFormat=" + getDDMFormat() +
                ", DDMCorrelId=" + getDDMCorrelId() +
                ", DDMLength2=" + getDDMLength2() +
                ", DDMCodePoint=" + getDDMCodePoint() +
                '}';
    }
}
