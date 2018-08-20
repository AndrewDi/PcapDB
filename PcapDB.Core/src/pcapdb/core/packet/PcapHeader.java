package pcapdb.core.packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.buffer.ByteBufferLocater;
import pcapdb.core.buffer.MappedByteBufferLocater;
import pcapdb.core.frame.LinkType;
import pcapdb.core.frame.PcapHeaderFrame;

import java.nio.ByteOrder;

public class PcapHeader extends AbstractPacket{
    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public PcapHeader(ByteBufferLocater byteBufferLocater){
        super(byteBufferLocater);
    }

    @Override
    public ByteBufferLocater getPayload() {
        return new ByteBufferLocater(this.byteBufferLocater,this.byteBufferLocater.getBaseOffset()+PcapHeaderFrame.totalLength);
    }

    public String getiMagic() {
        return this.byteBufferLocater.getByteString(PcapHeaderFrame.iMagicPosition,PcapHeaderFrame.iMagicLength, ByteOrder.BIG_ENDIAN);
    }

    public short getiMaVersion(){
        return this.byteBufferLocater.getShort(PcapHeaderFrame.iMaVersionPosition);
    }

    public int getiMiVersion(){
        return this.byteBufferLocater.getShort(PcapHeaderFrame.iMiVersionPosition);
    }

    public int getiTimezone(){
        return this.byteBufferLocater.getInt(PcapHeaderFrame.iTimezonePosition);
    }

    public int getiSigFlags(){
        return this.byteBufferLocater.getInt(PcapHeaderFrame.iSigFlagsPosition);
    }

    public int getiSnapLen(){
        return this.byteBufferLocater.getInt(PcapHeaderFrame.iSnapLenPosition);
    }

    public LinkType getiLinkType(){
        return LinkType.valueOf(this.byteBufferLocater.getInt(PcapHeaderFrame.iLinkTypePosition));
    }

    @Override
    public String toString() {
        return "PcapHeader{" +
                "iMagic="+this.getiMagic() +
                ", iMaVersion="+this.getiMaVersion() +
                ", iMiVersion="+this.getiMiVersion() +
                ", iTimezone="+this.getiTimezone() +
                ", iSigFlags="+this.getiSigFlags() +
                ", iSnapLen="+this.getiSnapLen() +
                ", iLinkType="+this.getiLinkType() +
                '}';
    }
}