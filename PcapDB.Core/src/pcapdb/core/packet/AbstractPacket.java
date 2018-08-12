package pcapdb.core.packet;

import pcapdb.core.buffer.MappedByteBufferLocater;

public abstract class AbstractPacket {
    protected MappedByteBufferLocater mappedByteBufferLocater;

    protected AbstractPacket Parent=null;

    public AbstractPacket getParent() {
        return Parent;
    }

    public AbstractPacket(MappedByteBufferLocater _mappedByteBufferLocater){
        this.mappedByteBufferLocater=_mappedByteBufferLocater;
    }

    public abstract MappedByteBufferLocater getPayload();

}
