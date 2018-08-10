package pcapdb.core.packet;

import pcapdb.core.buffer.MappedByteBufferLocater;

public abstract class AbstractPacket {
    protected MappedByteBufferLocater mappedByteBufferLocater;


    public AbstractPacket(){}

    public AbstractPacket(MappedByteBufferLocater _mappedByteBufferLocater){
        this.mappedByteBufferLocater=_mappedByteBufferLocater;
    }


}
