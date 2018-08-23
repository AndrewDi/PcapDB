package pcapdb.core.packet;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ListMultimap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.buffer.ByteBufferLocater;
import pcapdb.core.frame.*;

import java.nio.ByteOrder;

public class DrdaPacket extends AbstractPacket {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    private ListMultimap<DrdaCodePointType,DrdaDDMParameter> drdaDDMParameters;

    public DrdaPacket(ByteBufferLocater byteBufferLocater, AbstractPacket abstractPacket) {
        super(byteBufferLocater, abstractPacket);
    }

    public ListMultimap<DrdaCodePointType,DrdaDDMParameter> getDrdaDDMParameters() {
        if (this.drdaDDMParameters == null) this.drdaDDMParameters = ArrayListMultimap.create();
        if (this.drdaDDMParameters.size() > 0) return this.drdaDDMParameters;

        int offset = DrdaFrame.totalLength;
        int drdaPacketLength = this.byteBufferLocater.getLength();

        //Deal with SQLCARD Payload
        if(this.getDDMCodePoint()==DrdaCodePointType.SQLCARD&&drdaPacketLength>offset+1){
            int SQL_CODE=0;
            if(this.byteBufferLocater.getByte(offset+1)==0x00) {
                SQL_CODE = this.byteBufferLocater.getInt(offset + 1, ByteOrder.LITTLE_ENDIAN);
            }
            else {
                SQL_CODE = this.byteBufferLocater.getInt(offset + 1, ByteOrder.BIG_ENDIAN);
            }
            //String SQL_CODE = this.byteBufferLocater.getUTF8String(offset+1,4);
            String SQL_STATE = this.byteBufferLocater.getUTF8String(offset+5,5);
            String SQL_ERRPROC = this.byteBufferLocater.getUTF8String(offset+10,8);
            SQLResult sqlResult = new SQLResult(SQL_CODE,SQL_STATE,SQL_ERRPROC);
            DrdaDDMParameter drdaDDMParameter = new DrdaDDMParameter();
            drdaDDMParameter.setDrdaCodePointType(DrdaCodePointType.SQLCARD);
            drdaDDMParameter.setData(sqlResult);
            this.drdaDDMParameters.put(DrdaCodePointType.SQLCARD,drdaDDMParameter);
            return this.drdaDDMParameters;
        }

        if(this.getDDMCodePoint()==DrdaCodePointType.RDBCMM||this.getDDMCodePoint()==DrdaCodePointType.RDBRLLBCK){
            DrdaDDMParameter drdaDDMParameter = new DrdaDDMParameter();
            drdaDDMParameter.setDrdaCodePointType(this.getDDMCodePoint());
            this.drdaDDMParameters.put(this.getDDMCodePoint(),drdaDDMParameter);
            return this.drdaDDMParameters;
        }

        while (offset < drdaPacketLength) {
            int length = this.byteBufferLocater.getShort(offset, ByteOrder.LITTLE_ENDIAN);
            DrdaCodePointType drdaCodePointType = DrdaCodePointType.valueOf(this.byteBufferLocater.getShort(offset + DrdaFrame.DDMLengthLength, ByteOrder.LITTLE_ENDIAN));
            if (length == 0 || getDDMCodePoint() == DrdaCodePointType.SQLSTT || getDDMCodePoint() == DrdaCodePointType.QRYDTA ||
                    getDDMCodePoint() == DrdaCodePointType.QRYDSC) {
                length = drdaPacketLength - DrdaFrame.totalLength - (DrdaFrame.DDMParameterLengthLength + DrdaFrame.DDMParameterCodePointLength);
            }

            DrdaDDMParameter drdaDDMParameter = new DrdaDDMParameter();
            drdaDDMParameter.setLength(length);
            drdaDDMParameter.setDrdaCodePointType(drdaCodePointType);

            int startIndex = offset + DrdaFrame.DDMParameterLengthLength + DrdaFrame.DDMParameterCodePointLength;
            int strlength = length;
            switch (drdaCodePointType) {
                case DATA:
                case QRYDTA:
                    strlength -= 1;
                    startIndex+=1;
                    drdaDDMParameter.setData(this.byteBufferLocater.getUTF8String(startIndex, strlength).trim());
                    break;
                case PRDDTA:
                    startIndex+=1;
                    strlength -= 4;
                    drdaDDMParameter.setData(this.byteBufferLocater.getEbcdicString(startIndex, strlength).trim());
                    break;
                case RDBACCCL:
                case QRYPRCTYP:
                    drdaDDMParameter.setData(DrdaCodePointType.valueOf(this.byteBufferLocater.getShort(startIndex, ByteOrder.LITTLE_ENDIAN)));
                    break;
                case PKGNAMCSN:
                     strlength -= 16;
                     String data = this.byteBufferLocater.getEbcdicString(startIndex, strlength).trim();
                     if(!data.contains("NULLID")){
                         data = this.byteBufferLocater.getUTF8String(startIndex,strlength);
                     }
                     drdaDDMParameter.setData(data);
                     break;
                case PKGSNLST:
                    strlength-=24;
                    startIndex+=4;
                    drdaDDMParameter.setData(this.byteBufferLocater.getEbcdicString(startIndex, strlength).trim());
                    break;
                case RSLSETFLG:
                    strlength-=1;
                    drdaDDMParameter.setData(this.byteBufferLocater.getByteString(startIndex,strlength,ByteOrder.LITTLE_ENDIAN).trim());
                    break;
                case QRYBLKSZ:
                case MAXRSLCNT:
                case MAXBLKEXT:
                    drdaDDMParameter.setData(this.byteBufferLocater.getShort(startIndex, ByteOrder.LITTLE_ENDIAN));
                    break;
                case SVRCOD:
                    drdaDDMParameter.setData(SVRCODLevel.valueOf(this.byteBufferLocater.getShort(startIndex, ByteOrder.LITTLE_ENDIAN)));
                    break;
                case SECCHKCD:
                    drdaDDMParameter.setData(SECCHKCDReson.ValueOf(this.byteBufferLocater.getByte(startIndex)));
                    break;
                case UOWDSP:
                    drdaDDMParameter.setData(UOWDSP.valueOf(this.byteBufferLocater.getByte(startIndex)));
                    break;
                default:
                    strlength -= 4;
                    drdaDDMParameter.setData(this.byteBufferLocater.getEbcdicString(startIndex, strlength).trim());
                    break;

            }
            this.drdaDDMParameters.put(drdaDDMParameter.getDrdaCodePointType(),drdaDDMParameter);
            offset += length;
        }
        return this.drdaDDMParameters;
    }

    @Override
    public ByteBufferLocater getPayload() {
        return null;
    }

    public int getDDMLength() {
        return this.byteBufferLocater.getShort(DrdaFrame.DDMLengthPosition, ByteOrder.LITTLE_ENDIAN);
    }

    public String getDDMMagic() {
        return this.byteBufferLocater.getByteStrig(DrdaFrame.DDMMagicPosition);
    }

    public byte getDDMFormat() {
        return this.byteBufferLocater.getByte(DrdaFrame.DDMFormatPosition);
    }

    public int getDDMCorrelId() {
        return this.byteBufferLocater.getShort(DrdaFrame.DDMCorrelIdPosition, ByteOrder.LITTLE_ENDIAN);
    }

    public int getDDMLength2() {
        return this.byteBufferLocater.getShort(DrdaFrame.DDMLength2Position, ByteOrder.LITTLE_ENDIAN);
    }

    public DrdaCodePointType getDDMCodePoint() {
        return DrdaCodePointType.valueOf(this.byteBufferLocater.getShort(DrdaFrame.DDMCodePointPosition, ByteOrder.LITTLE_ENDIAN));
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
