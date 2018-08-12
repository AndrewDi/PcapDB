package pcapdb.core.engine;

import pcapdb.core.buffer.MappedByteBufferLocater;
import pcapdb.core.packet.AbstractPacket;

public class PcapScanner {
    private MappedByteBufferLocater mappedByteBufferLocater;
    private AbstractPacket abstractPacket;

    public PcapScanner(MappedByteBufferLocater _mappedByteBufferLocater,AbstractPacket abstractPacket){
        this.mappedByteBufferLocater=_mappedByteBufferLocater;
        this.abstractPacket=abstractPacket;
    }

    public MappedByteBufferLocater getNextPacket(){
        return this.abstractPacket.getPayload();
    }
}
