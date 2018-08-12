package pcapdb.core.packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.buffer.MappedByteBufferLocater;
import pcapdb.core.frame.LinkType;
import pcapdb.core.frame.PcapHeaderFrame;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapHeader extends AbstractPacket{
    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public PcapHeader(MappedByteBufferLocater _mappedByteBufferLocater){
        super(_mappedByteBufferLocater);
    }

    @Override
    public MappedByteBufferLocater getPayload() {
        return new MappedByteBufferLocater(this.mappedByteBufferLocater,this.mappedByteBufferLocater.getBaseOffset()+PcapHeaderFrame.totalLength);
    }

    public String getiMagic() {
        return this.mappedByteBufferLocater.getByteString(PcapHeaderFrame.iMagicPosition,PcapHeaderFrame.iMagicLength, ByteOrder.BIG_ENDIAN);
    }

    public short getiMaVersion(){
        return this.mappedByteBufferLocater.getShort(PcapHeaderFrame.iMaVersionPosition);
    }

    public int getiMiVersion(){
        return this.mappedByteBufferLocater.getShort(PcapHeaderFrame.iMiVersionPosition);
    }

    public int getiTimezone(){
        return this.mappedByteBufferLocater.getInt(PcapHeaderFrame.iTimezonePosition);
    }

    public int getiSigFlags(){
        return this.mappedByteBufferLocater.getInt(PcapHeaderFrame.iSigFlagsPosition);
    }

    public int getiSnapLen(){
        return this.mappedByteBufferLocater.getInt(PcapHeaderFrame.iSnapLenPosition);
    }

    public LinkType getiLinkType(){
        return LinkType.valueOf(this.mappedByteBufferLocater.getInt(PcapHeaderFrame.iLinkTypePosition));
    }

    @Override
    public String toString() {
        logger.debug(new PcapHeaderFrame().toString());
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