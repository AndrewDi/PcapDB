package pcapdb.core.packet;

import pcapdb.core.buffer.MappedByteBufferLocater;

/**
 * All packet should extends on this abstract packets
 *
 * @author PanDi(anonymous-oss@outlook.com)
 */
public abstract class AbstractPacket {
    MappedByteBufferLocater mappedByteBufferLocater;

    AbstractPacket parent =null;

    public AbstractPacket getParent() {
        return parent;
    }

    AbstractPacket(MappedByteBufferLocater mappedByteBufferLocater, AbstractPacket abstractPacket){
        this.mappedByteBufferLocater=mappedByteBufferLocater;
        this.parent = abstractPacket;
    }

    AbstractPacket(MappedByteBufferLocater mappedByteBufferLocater){
        this.mappedByteBufferLocater=mappedByteBufferLocater;
    }

    public abstract MappedByteBufferLocater getPayload();

}
