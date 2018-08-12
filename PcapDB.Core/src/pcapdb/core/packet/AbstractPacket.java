package pcapdb.core.packet;

import pcapdb.core.buffer.MappedByteBufferLocater;

public abstract class AbstractPacket {
    protected MappedByteBufferLocater mappedByteBufferLocater;

    protected AbstractPacket parent =null;

    public AbstractPacket getParent() {
        return parent;
    }

    public AbstractPacket(MappedByteBufferLocater _mappedByteBufferLocater, AbstractPacket _packet){
        this.mappedByteBufferLocater=_mappedByteBufferLocater;
        this.parent = _packet;
    }

    public AbstractPacket(MappedByteBufferLocater _mappedByteBufferLocater){
        this.mappedByteBufferLocater=_mappedByteBufferLocater;
    }

    public abstract MappedByteBufferLocater getPayload();

}
